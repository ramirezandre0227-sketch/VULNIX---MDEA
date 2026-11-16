<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Evidence;
use App\Models\Finding;
use App\Models\ScanJob;
use App\Support\Access;
use App\Support\Audit;
use App\Support\DataStore;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class FindingController extends Controller
{
    /** GET /findings/{id}: detalle, evidencias, recomendaciones y excepciones. */
    public function show(Request $request, Finding $finding): JsonResponse
    {
        $finding->load('analysis.version.project', 'recommendations', 'evidences', 'exceptions.requester', 'exceptions.approver', 'job.analyzer');
        Access::ensureAnalysis($request->user(), $finding->analysis);

        return response()->json(['data' => $finding->toApiArray() + [
            'snippet' => $finding->snippet,
            'metadata' => $finding->metadata,
            'analyzer_version' => $finding->job?->analyzer?->version,
            'evidences' => $finding->evidences->map->toApiArray()->values(),
            'job_evidences' => Evidence::where('job_id', $finding->job_id)->whereNull('finding_id')->get()->map->toApiArray()->values(),
            'recommendations' => $finding->recommendations->map(fn ($r) => [
                'description' => $r->description, 'verify' => $r->verify, 'references' => $r->references,
            ])->values(),
            'exceptions' => $finding->exceptions->map->toApiArray()->values(),
            'project' => ['id' => $finding->analysis->version->project_id, 'name' => $finding->analysis->version->project->name],
        ]]);
    }

    /** GET /evidences/{id}/download: evidencia redactada, con verificación de integridad. */
    public function downloadEvidence(Request $request, Evidence $evidence, DataStore $store): Response
    {
        $job = $evidence->job_id ? ScanJob::find($evidence->job_id) : Finding::find($evidence->finding_id)?->job;
        $job->load('analysis.version.project');
        Access::ensureAnalysis($request->user(), $job->analysis);
        $contents = $store->read($evidence->uri);
        $ok = hash('sha256', $contents) === $evidence->sha256;
        Audit::log('evidence.downloaded', 'evidence', $evidence->id, ['integrity_ok' => $ok]);

        return response($contents, 200, [
            'Content-Type' => 'application/octet-stream',
            'Content-Disposition' => 'attachment; filename="evidence-'.$evidence->id.'.json"',
            'X-Vulnix-SHA256' => $evidence->sha256,
            'X-Vulnix-Integrity' => $ok ? 'verified' : 'MISMATCH',
        ]);
    }
}
