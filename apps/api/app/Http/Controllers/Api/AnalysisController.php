<?php

namespace App\Http\Controllers\Api;

use App\Enums\AnalysisStatus;
use App\Enums\JobStatus;
use App\Exceptions\VulnixException;
use App\Http\Controllers\Controller;
use App\Models\Analysis;
use App\Models\Finding;
use App\Models\ProjectVersion;
use App\Models\ScanJob;
use App\Services\AnalysisPlanner;
use App\Services\DecisionService;
use App\Services\VersionComparator;
use App\Support\Access;
use App\Support\Audit;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;

class AnalysisController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $user = $request->user();
        $query = Analysis::query()->with('version.project', 'latestDecision', 'policy', 'requester')->orderByDesc('created_at');
        if (! $user->canDo('projects.view_all')) {
            $query->whereHas('version.project', fn ($q) => $q->where('owner_id', $user->id));
        }
        if ($status = $request->query('status')) {
            $query->where('status', $status);
        }
        $page = $query->paginate(min((int) $request->integer('per_page', 25), 100));

        return response()->json([
            'data' => collect($page->items())->map(fn (Analysis $a) => $a->toApiArray() + ['decision' => $a->latestDecision?->result->value]),
            'meta' => ['page' => $page->currentPage(), 'per_page' => $page->perPage(), 'total' => $page->total()],
        ]);
    }

    /** POST /analyses -> 202 + analysis_id (manual §6). Admite cabecera Idempotency-Key. */
    public function store(Request $request, AnalysisPlanner $planner): JsonResponse
    {
        $data = $request->validate([
            'project_version_id' => ['required', 'uuid'],
            'profile' => ['nullable', 'string', 'regex:/^[a-z0-9-]{3,64}$/'],
            'dynamic_testing' => ['nullable', 'array'],
            'dynamic_testing.enabled' => ['nullable', 'boolean'],
            'dynamic_testing.target_url' => ['nullable', 'string', 'max:255', 'url:http,https'],
        ]);
        $key = $request->header('Idempotency-Key');
        if ($key !== null && ! preg_match('/^[A-Za-z0-9_-]{8,128}$/', $key)) {
            throw new VulnixException('IDEMPOTENCY_KEY_INVALID', 'Idempotency-Key inválida.');
        }
        $version = ProjectVersion::with('project')->findOrFail($data['project_version_id']);
        Access::ensureProject($request->user(), $version->project);
        $profile = $data['profile'] ?? $version->project->default_profile;

        $analysis = $planner->plan($version, $profile, $data['dynamic_testing'] ?? [], $request->user(), $key);

        return response()->json(['analysis_id' => $analysis->id, 'status' => $analysis->status->value], 202);
    }

    public function show(Request $request, Analysis $analysis): JsonResponse
    {
        $analysis->load('version.project', 'policy', 'requester', 'latestDecision');
        Access::ensureAnalysis($request->user(), $analysis);
        $jobs = $analysis->jobs()->with('analyzer')->get();
        $counts = Finding::where('analysis_id', $analysis->id)->select('severity', DB::raw('count(*) as n'))->groupBy('severity')->pluck('n', 'severity');

        return response()->json(['data' => $analysis->toApiArray() + [
            'jobs' => $jobs->map->toApiArray()->values(),
            'findings_by_severity' => $counts,
            'decision' => $analysis->latestDecision?->toApiArray(),
        ]]);
    }

    /** GET /analyses/{id}/findings: paginado y filtrable. */
    public function findings(Request $request, Analysis $analysis): JsonResponse
    {
        $analysis->load('version.project');
        Access::ensureAnalysis($request->user(), $analysis);
        $filters = $request->validate([
            'severity' => ['nullable', Rule::in(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'])],
            'category' => ['nullable', Rule::in(['sast', 'sca', 'secrets', 'quality', 'dast'])],
            'analyzer' => ['nullable', 'string', 'max:64'],
            'q' => ['nullable', 'string', 'max:120'],
            'per_page' => ['nullable', 'integer', 'min:1', 'max:200'],
        ]);
        $query = Finding::query()->where('analysis_id', $analysis->id)
            ->orderByRaw("CASE severity WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END DESC")
            ->orderBy('file_path')->orderBy('start_line');
        foreach (['severity', 'category'] as $f) {
            if (! empty($filters[$f])) {
                $query->where($f, $filters[$f]);
            }
        }
        if (! empty($filters['analyzer'])) {
            $query->where('analyzer_name', $filters['analyzer']);
        }
        if (! empty($filters['q'])) {
            $like = '%'.addcslashes($filters['q'], '%_\\').'%';
            $query->where(fn ($q) => $q->where('title', 'ilike', $like)->orWhere('file_path', 'ilike', $like)->orWhere('rule_id', 'ilike', $like));
        }
        $page = $query->withCount(['exceptions as pending_exceptions' => fn ($q) => $q->where('status', 'PENDING')])
            ->paginate($filters['per_page'] ?? 50);

        return response()->json([
            'data' => collect($page->items())->map(fn (Finding $f) => $f->toApiArray() + ['pending_exceptions' => $f->pending_exceptions]),
            'meta' => ['page' => $page->currentPage(), 'per_page' => $page->perPage(), 'total' => $page->total()],
        ]);
    }

    /** POST /analyses/{id}/evaluate: decisión firmada o estado inconcluso. */
    public function evaluate(Request $request, Analysis $analysis, DecisionService $decisions): JsonResponse
    {
        $analysis->load('version.project');
        Access::ensureAnalysis($request->user(), $analysis);
        $decision = $decisions->decide($analysis, $request->user(), 'USER');

        return response()->json(['data' => $decision->toApiArray()], 201);
    }

    public function cancel(Request $request, Analysis $analysis): JsonResponse
    {
        $analysis->load('version.project');
        Access::ensureAnalysis($request->user(), $analysis);
        if (! $analysis->status->canTransitionTo(AnalysisStatus::Cancelled)) {
            throw VulnixException::conflict('ANALYSIS_NOT_CANCELLABLE', 'El análisis ya no puede cancelarse.', ['status' => $analysis->status->value]);
        }
        DB::transaction(function () use ($analysis, $request) {
            ScanJob::where('analysis_id', $analysis->id)->whereIn('status', [JobStatus::Queued->value, JobStatus::Running->value])
                ->update(['status' => JobStatus::Cancelled->value, 'ended_at' => now(), 'error_type' => 'CANCELLED_BY_USER']);
            $analysis->transitionTo(AnalysisStatus::Cancelled, 'Cancelado por '.$request->user()->username);
            Audit::log('analysis.cancelled', 'analysis', $analysis->id);
        });

        return response()->json(['data' => ['id' => $analysis->id, 'status' => $analysis->status->value]]);
    }

    /** GET /analyses/{id}/compare/{other}: nuevos, corregidos y persistentes respecto a otro análisis. */
    public function compare(Request $request, Analysis $analysis, Analysis $other, VersionComparator $comparator): JsonResponse
    {
        $analysis->load('version.project');
        $other->load('version.project');
        Access::ensureAnalysis($request->user(), $analysis);
        Access::ensureAnalysis($request->user(), $other);
        if ($analysis->version->project_id !== $other->version->project_id) {
            throw new VulnixException('COMPARE_DIFFERENT_PROJECTS', 'Solo se pueden comparar análisis del mismo proyecto.');
        }

        return response()->json(['data' => $comparator->compare($other, $analysis)]);
    }
}
