<?php

namespace App\Http\Controllers\Api;

use App\Exceptions\VulnixException;
use App\Http\Controllers\Controller;
use App\Models\Analysis;
use App\Services\Reports\ReportGenerator;
use App\Services\Signing\DecisionSigner;
use App\Support\Access;
use App\Support\Audit;
use App\Support\DataStore;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class DecisionController extends Controller
{
    /** GET /analyses/{id}/decision: decisión vigente + historial. */
    public function show(Request $request, Analysis $analysis): JsonResponse
    {
        $analysis->load('version.project', 'decisions');
        Access::ensureAnalysis($request->user(), $analysis);
        $latest = $analysis->decisions->first();
        if (! $latest) {
            throw new VulnixException('DECISION_NOT_FOUND', 'Aún no se ha emitido una decisión para este análisis.', 404);
        }

        return response()->json(['data' => $latest->toApiArray() + [
            'checks' => $latest->reason_json['checks'] ?? [],
            'history' => $analysis->decisions->map(fn ($d) => [
                'id' => $d->id, 'result' => $d->result->value, 'issued_at' => $d->issued_at->toIso8601String(), 'issued_via' => $d->issued_via,
            ])->values(),
        ]]);
    }

    /** GET /analyses/{id}/decision/token: documento firmado (JWS) para el gate de despliegue. */
    public function token(Request $request, Analysis $analysis, DataStore $store): Response
    {
        $analysis->load('version.project', 'latestDecision');
        Access::ensureAnalysis($request->user(), $analysis);
        $decision = $analysis->latestDecision ?? throw new VulnixException('DECISION_NOT_FOUND', 'No hay decisión emitida.', 404);
        $token = $store->read($decision->signed_token_uri);
        if (hash('sha256', $token) !== $decision->token_sha256) {
            throw new VulnixException('DECISION_TAMPERED', 'El documento firmado no coincide con su hash registrado.', 500);
        }
        Audit::log('decision.token_downloaded', 'decision', $decision->id, ['result' => $decision->result->value]);

        return response($token, 200, [
            'Content-Type' => 'application/jose',
            'Content-Disposition' => 'attachment; filename="vulnix-authorization-'.$analysis->id.'.jws"',
            'X-Vulnix-Result' => $decision->result->value,
        ]);
    }

    /** GET /authorization/public-key: clave pública para verificación fuera de línea. */
    public function publicKey(DecisionSigner $signer): JsonResponse
    {
        return response()->json(['data' => [
            'alg' => 'EdDSA', 'crv' => 'Ed25519', 'typ' => DecisionSigner::TYP,
            'kid' => $signer->keyId(), 'public_key_b64' => $signer->publicKeyB64(), 'issuer' => config('vulnix.issuer'),
        ]]);
    }

    /** POST /authorization/verify: verificación asistida (los pipelines deben verificar fuera de línea). */
    public function verify(Request $request, DecisionSigner $signer): JsonResponse
    {
        $data = $request->validate([
            'token' => ['required', 'string', 'max:8192'],
            'artifact_sha256' => ['required', 'string', 'regex:/^[A-Fa-f0-9]{64}$/'],
        ]);
        $result = $signer->verify($data['token'], $data['artifact_sha256']);
        Audit::log('authorization.verified', 'analysis', $result['claims']['analysis_id'] ?? null, [
            'valid' => $result['valid'], 'errors' => $result['errors'], 'artifact_sha256' => strtolower($data['artifact_sha256']),
        ]);

        return response()->json(['data' => $result], $result['valid'] ? 200 : 422);
    }

    /** GET /analyses/{id}/report?format=json|sarif|html|pdf */
    public function report(Request $request, Analysis $analysis, ReportGenerator $reports, DataStore $store): Response
    {
        $analysis->load('version.project');
        Access::ensureAnalysis($request->user(), $analysis);
        if (! $request->user()->canDo('reports.download') && $request->user()->id !== $analysis->version->project->owner_id) {
            throw VulnixException::forbidden();
        }
        $format = (string) $request->query('format', 'json');
        $report = $reports->generate($analysis, $format, $request->user());
        $contents = $store->read($report->uri);
        $ext = $format === 'sarif' ? 'sarif' : $format;

        return response($contents, 200, [
            'Content-Type' => ReportGenerator::FORMATS[$format].($format === 'pdf' ? '' : '; charset=utf-8'),
            'Content-Disposition' => 'attachment; filename="vulnix-'.$analysis->id.'.'.$ext.'"',
            'X-Vulnix-SHA256' => $report->sha256,
        ]);
    }
}
