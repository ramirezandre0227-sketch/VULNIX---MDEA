<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Analysis;
use App\Models\Analyzer;
use App\Models\Project;
use App\Services\Signing\DecisionSigner;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Throwable;

class DashboardController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $user = $request->user();
        $all = $user->canDo('projects.view_all');
        $projectIds = $all ? null : Project::where('owner_id', $user->id)->pluck('id');

        $analyses = Analysis::query()
            ->when(! $all, fn ($q) => $q->whereHas('version', fn ($v) => $v->whereIn('project_id', $projectIds)));

        $statusCounts = (clone $analyses)->select('status', DB::raw('count(*) as n'))->groupBy('status')->pluck('n', 'status');

        // Resultado de la decisión vigente por análisis.
        $decisionCounts = DB::table('evaluation.decisions as d')
            ->join(DB::raw('(SELECT analysis_id, max(created_at) AS m FROM evaluation.decisions GROUP BY analysis_id) last'),
                fn ($j) => $j->on('last.analysis_id', '=', 'd.analysis_id')->on('last.m', '=', 'd.created_at'))
            ->join('evaluation.analyses as a', 'a.id', '=', 'd.analysis_id')
            ->join('catalog.project_versions as v', 'v.id', '=', 'a.version_id')
            ->when(! $all, fn ($q) => $q->whereIn('v.project_id', $projectIds))
            ->select('d.result', DB::raw('count(*) as n'))->groupBy('d.result')->pluck('n', 'result');

        $severityCounts = DB::table('evaluation.findings as f')
            ->join('evaluation.analyses as a', 'a.id', '=', 'f.analysis_id')
            ->join('catalog.project_versions as v', 'v.id', '=', 'a.version_id')
            ->where('f.created_at', '>=', now()->subDays(30))
            ->when(! $all, fn ($q) => $q->whereIn('v.project_id', $projectIds))
            ->select('f.severity', DB::raw('count(*) as n'))->groupBy('f.severity')->pluck('n', 'severity');

        $recent = (clone $analyses)->with('version.project', 'latestDecision', 'policy', 'requester')
            ->orderByDesc('created_at')->limit(10)->get()
            ->map(fn (Analysis $a) => $a->toApiArray() + ['decision' => $a->latestDecision?->result->value]);

        return response()->json(['data' => [
            'projects' => $all ? Project::count() : $projectIds->count(),
            'analyses_by_status' => $statusCounts,
            'decisions_by_result' => $decisionCounts,
            'findings_last_30d_by_severity' => $severityCounts,
            'recent_analyses' => $recent,
            'intel' => $this->intelFreshness(),
        ]]);
    }

    /** GET /system/health: estado de componentes (BD, claves, almacenamiento, orquestador, analizadores). */
    public function health(DecisionSigner $signer): JsonResponse
    {
        $dataDir = config('vulnix.data_dir');
        $analyzers = Analyzer::query()->orderBy('name')->orderByDesc('last_seen_at')->get()->unique('name')->values();
        $orchestratorAlive = $analyzers->contains(fn ($a) => $a->last_seen_at && $a->last_seen_at->gt(now()->subMinutes(3)));

        $analyzerApi = ['reachable' => false];
        try {
            $resp = Http::timeout(2)->withHeaders(['X-Vulnix-Service-Token' => (string) config('vulnix.internal_token')])
                ->get(rtrim(config('vulnix.analyzer_api_url'), '/').'/internal/v1/health');
            $analyzerApi = ['reachable' => $resp->successful(), 'status' => $resp->json('status')];
        } catch (Throwable) {
            // inalcanzable: se informa como tal
        }

        $queue = DB::table('evaluation.scan_jobs')->select('status', DB::raw('count(*) as n'))
            ->whereIn('status', ['QUEUED', 'RUNNING'])->groupBy('status')->pluck('n', 'status');

        return response()->json(['data' => [
            'database' => true,
            'signing_key' => $signer->hasKeys() ? ['present' => true, 'key_id' => $signer->keyId()] : ['present' => false],
            'storage' => ['writable' => is_dir($dataDir) && is_writable($dataDir), 'free_bytes' => is_dir($dataDir) ? @disk_free_space($dataDir) : null],
            'orchestrator' => ['alive' => $orchestratorAlive],
            'analyzer_api' => $analyzerApi,
            'queue' => $queue,
            'analyzers' => $analyzers->map(fn ($a) => [
                'name' => $a->name, 'version' => $a->version, 'category' => $a->category, 'healthy' => $a->healthy,
                'last_seen_at' => $a->last_seen_at?->toIso8601String(), 'detail' => $a->metadata['detail'] ?? null,
            ]),
            'intel' => $this->intelFreshness(),
        ]]);
    }

    private function intelFreshness(): array
    {
        return DB::table('catalog.intel_feeds')->select('ecosystem', DB::raw('max(imported_at) as imported_at'), DB::raw('max(record_count) as records'))
            ->groupBy('ecosystem')->get()
            ->map(fn ($r) => ['ecosystem' => $r->ecosystem, 'imported_at' => $r->imported_at, 'records' => (int) $r->records,
                'age_days' => round(now()->diffInHours($r->imported_at, true) / 24, 1)])
            ->all();
    }
}
