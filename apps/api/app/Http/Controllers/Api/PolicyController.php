<?php

namespace App\Http\Controllers\Api;

use App\Exceptions\VulnixException;
use App\Http\Controllers\Controller;
use App\Models\Policy;
use App\Services\Policy\PolicyLoader;
use App\Support\Audit;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class PolicyController extends Controller
{
    public function index(): JsonResponse
    {
        $policies = Policy::with('creator', 'approver')->orderBy('code')->orderByDesc('created_at')->get();

        return response()->json(['data' => $policies->map->toApiArray()->values()]);
    }

    public function show(Policy $policy): JsonResponse
    {
        return response()->json(['data' => $policy->load('creator', 'approver')->toApiArray(true)]);
    }

    /** POST /policies: nueva versión (DRAFT). El contenido es inmutable; requiere aprobación de otra persona. */
    public function store(Request $request, PolicyLoader $loader): JsonResponse
    {
        $data = $request->validate(['yaml' => ['required', 'string', 'max:65536']]);
        $parsed = $loader->fromYaml($data['yaml']);
        if (Policy::where('code', $parsed['code'])->where('version', $parsed['version'])->exists()) {
            throw VulnixException::conflict('POLICY_VERSION_EXISTS', 'Esa versión de la política ya existe: las políticas son inmutables, cree una versión nueva.');
        }
        $policy = Policy::create([
            'code' => $parsed['code'],
            'version' => $parsed['version'],
            'rules_json' => $parsed['rules'],
            'sha256' => $parsed['sha256'],
            'source_yaml' => $parsed['source'],
            'status' => 'DRAFT',
            'created_by' => $request->user()->id,
        ]);
        Audit::log('policy.created', 'policy', $policy->id, ['code' => $policy->code, 'version' => $policy->version, 'sha256' => $policy->sha256]);

        return response()->json(['data' => $policy->load('creator')->toApiArray(true)], 201);
    }

    /** POST /policies/{id}/approve: activa la versión y retira las anteriores del mismo código. */
    public function approve(Request $request, Policy $policy): JsonResponse
    {
        if ($policy->status !== 'DRAFT') {
            throw VulnixException::conflict('POLICY_NOT_DRAFT', 'Solo se pueden aprobar políticas en borrador.');
        }
        if ($policy->created_by === $request->user()->id) {
            throw VulnixException::forbidden('Segregación de funciones: quien crea la política no puede aprobarla.');
        }
        DB::transaction(function () use ($policy, $request) {
            Policy::where('code', $policy->code)->where('status', 'ACTIVE')->update(['status' => 'RETIRED']);
            $policy->forceFill(['status' => 'ACTIVE', 'approved_by' => $request->user()->id, 'approved_at' => now()])->save();
            Audit::log('policy.approved', 'policy', $policy->id, ['code' => $policy->code, 'version' => $policy->version, 'sha256' => $policy->sha256]);
        });

        return response()->json(['data' => $policy->fresh(['creator', 'approver'])->toApiArray()]);
    }
}
