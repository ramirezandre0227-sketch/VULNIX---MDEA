<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Analysis;
use App\Models\Policy;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Services\Ingest\ArtifactIngestor;
use App\Support\Access;
use App\Support\Audit;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;

class ProjectController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $user = $request->user();
        $query = Access::scopeProjects(Project::query()->with('owner'), $user)->orderByDesc('created_at');
        if ($q = $request->string('q')->trim()->value()) {
            $query->where('name', 'ilike', '%'.addcslashes($q, '%_\\').'%');
        }
        $page = $query->paginate(min((int) $request->integer('per_page', 25), 100));

        $items = collect($page->items())->map(function (Project $p) {
            $latest = $p->versions()->first();
            $analysis = $latest ? Analysis::where('version_id', $latest->id)->with('latestDecision')->latest('created_at')->first() : null;

            return $this->projectArray($p) + [
                'latest_version' => $latest ? ['id' => $latest->id, 'version' => $latest->version, 'created_at' => $latest->created_at?->toIso8601String()] : null,
                'latest_analysis' => $analysis ? [
                    'id' => $analysis->id, 'status' => $analysis->status->value,
                    'decision' => $analysis->latestDecision?->result->value,
                ] : null,
            ];
        });

        return response()->json(['data' => $items, 'meta' => ['page' => $page->currentPage(), 'per_page' => $page->perPage(), 'total' => $page->total()]]);
    }

    public function store(Request $request): JsonResponse
    {
        $profiles = Policy::query()->where('status', 'ACTIVE')->distinct()->pluck('code')->all();
        $data = $request->validate([
            'name' => ['required', 'string', 'min:3', 'max:150'],
            'description' => ['nullable', 'string', 'max:2000'],
            'criticality' => ['required', Rule::in(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])],
            'default_profile' => ['nullable', 'string', Rule::in($profiles)],
        ]);
        $base = Str::slug($data['name']) ?: 'project';
        $slug = $base;
        for ($i = 2; Project::where('slug', $slug)->exists(); $i++) {
            $slug = "{$base}-{$i}";
        }
        $project = Project::create([
            'name' => $data['name'],
            'slug' => $slug,
            'description' => $data['description'] ?? null,
            'owner_id' => $request->user()->id,
            'criticality' => $data['criticality'],
            'default_profile' => $data['default_profile'] ?? config('vulnix.default_profile'),
        ]);
        Audit::log('project.created', 'project', $project->id, ['name' => $project->name, 'criticality' => $project->criticality]);

        return response()->json(['data' => $this->projectArray($project->load('owner'))], 201);
    }

    public function show(Request $request, Project $project): JsonResponse
    {
        Access::ensureProject($request->user(), $project);
        $versions = $project->versions()->with(['analyses' => fn ($q) => $q->with('latestDecision', 'policy')])->get();

        return response()->json(['data' => $this->projectArray($project->load('owner')) + [
            'versions' => $versions->map(fn (ProjectVersion $v) => [
                'id' => $v->id,
                'version' => $v->version,
                'sha256' => $v->sha256,
                'artifact_kind' => $v->artifact_kind,
                'original_filename' => $v->original_filename,
                'size_bytes' => $v->size_bytes,
                'file_count' => $v->file_count,
                'technologies' => $v->technologies,
                'created_at' => $v->created_at?->toIso8601String(),
                'analyses' => $v->analyses->map(fn (Analysis $a) => [
                    'id' => $a->id, 'status' => $a->status->value, 'profile' => $a->profile,
                    'policy_version' => $a->policy?->version,
                    'decision' => $a->latestDecision?->result->value,
                    'created_at' => $a->created_at?->toIso8601String(),
                ])->values(),
            ])->values(),
        ]]);
    }

    /** POST /projects/{id}/versions: carga y registro de un artefacto inmutable. */
    public function storeVersion(Request $request, Project $project, ArtifactIngestor $ingestor): JsonResponse
    {
        Access::ensureProject($request->user(), $project);
        $maxKb = intdiv(config('vulnix.ingest.max_upload_bytes'), 1024);
        $data = $request->validate([
            'version' => ['required', 'string', 'regex:/^[A-Za-z0-9._+-]{1,64}$/'],
            'file' => ['required', 'file', "max:{$maxKb}"],
        ]);
        $version = $ingestor->ingest($project, $request->user(), $request->file('file'), $data['version']);

        return response()->json(['data' => [
            'id' => $version->id,
            'project_id' => $project->id,
            'version' => $version->version,
            'sha256' => $version->sha256,
            'artifact_kind' => $version->artifact_kind,
            'size_bytes' => $version->size_bytes,
            'file_count' => $version->file_count,
            'technologies' => $version->technologies,
        ]], 201);
    }

    private function projectArray(Project $p): array
    {
        return [
            'id' => $p->id,
            'name' => $p->name,
            'slug' => $p->slug,
            'description' => $p->description,
            'criticality' => $p->criticality,
            'default_profile' => $p->default_profile,
            'owner' => $p->owner?->username,
            'created_at' => $p->created_at?->toIso8601String(),
        ];
    }
}
