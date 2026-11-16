<?php

namespace App\Services\Reports;

use App\Enums\Severity;
use App\Exceptions\VulnixException;
use App\Models\Analysis;
use App\Models\Finding;
use App\Models\Report;
use App\Models\User;
use App\Support\Audit;
use App\Support\Canonical;
use App\Support\DataStore;
use Dompdf\Dompdf;
use Dompdf\Options;

/**
 * Reportes (manual §4): JSON, SARIF 2.1.0, HTML y PDF, con SHA-256 registrado para su integridad.
 * Un reporte queda ligado a la decisión vigente en el momento de generarlo.
 */
final class ReportGenerator
{
    public const FORMATS = ['json' => 'application/json', 'sarif' => 'application/sarif+json', 'html' => 'text/html', 'pdf' => 'application/pdf'];

    public function __construct(private readonly DataStore $store) {}

    public function generate(Analysis $analysis, string $format, ?User $actor): Report
    {
        if (! isset(self::FORMATS[$format])) {
            throw new VulnixException('REPORT_FORMAT_INVALID', 'Formato no soportado.', 422, ['allowed' => array_keys(self::FORMATS)]);
        }
        $analysis->load('version.project', 'policy', 'latestDecision', 'requester');
        $decision = $analysis->latestDecision;
        $existing = Report::query()->where('analysis_id', $analysis->id)->where('format', $format)
            ->where('decision_id', $decision?->id)->latest('created_at')->first();
        if ($existing && $this->store->sha256($existing->uri) === $existing->sha256) {
            return $existing;
        }

        $data = $this->collect($analysis);
        $contents = match ($format) {
            'json' => json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
            'sarif' => json_encode($this->sarif($data), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
            'html' => $this->html($data),
            'pdf' => $this->pdf($data),
        };
        $ext = $format === 'sarif' ? 'sarif.json' : $format;
        $tag = $decision?->id ?? 'no-decision-'.substr(hash('sha256', $contents), 0, 12);
        $stored = $this->store->putImmutable("reports/{$analysis->id}/{$tag}.{$ext}", $contents);

        $report = Report::create([
            'analysis_id' => $analysis->id,
            'decision_id' => $decision?->id,
            'format' => $format,
            'uri' => $stored['uri'],
            'sha256' => $stored['sha256'],
            'size_bytes' => $stored['size'],
            'created_by' => $actor?->id,
        ]);
        Audit::log('report.generated', 'analysis', $analysis->id, ['format' => $format, 'sha256' => $stored['sha256'], 'report_id' => $report->id], $actor);

        return $report;
    }

    public function collect(Analysis $analysis): array
    {
        $version = $analysis->version;
        $decision = $analysis->latestDecision;
        $jobs = $analysis->latestJobs();
        $findings = Finding::query()->where('analysis_id', $analysis->id)->with('recommendations')->get()
            ->sortBy([fn ($a, $b) => $b->severity->rank() <=> $a->severity->rank(), ['file_path', 'asc'], ['start_line', 'asc']])
            ->values();

        return [
            'schema' => 'vulnix.report/v1',
            'generated_at' => now()->toIso8601String(),
            'disclaimer' => 'VULNIX es un evaluador técnico: no certifica la ausencia total de vulnerabilidades.',
            'project' => ['id' => $version->project->id, 'name' => $version->project->name, 'criticality' => $version->project->criticality],
            'artifact' => [
                'version' => $version->version, 'sha256' => $version->sha256, 'kind' => $version->artifact_kind,
                'filename' => $version->original_filename, 'size_bytes' => $version->size_bytes, 'files' => $version->file_count,
                'technologies' => $version->technologies,
            ],
            'analysis' => $analysis->toApiArray(),
            'policy' => ['code' => $analysis->policy->code, 'version' => $analysis->policy->version,
                'sha256' => $analysis->policy->sha256, 'rules' => $analysis->policy->rules_json],
            'jobs' => $jobs->map->toApiArray()->values()->all(),
            'decision' => $decision?->toApiArray(),
            'decision_checks' => $decision?->reason_json['checks'] ?? [],
            'summary' => [
                'by_severity' => collect(Severity::cases())->mapWithKeys(fn ($s) => [$s->value => $findings->where('severity', $s)->count()])->all(),
                'by_category' => $findings->groupBy('category')->map->count()->all(),
                'total' => $findings->count(),
            ],
            'findings' => $findings->map(fn (Finding $f) => $f->toApiArray() + [
                'recommendations' => $f->recommendations->map(fn ($r) => ['description' => $r->description, 'verify' => $r->verify])->all(),
            ])->all(),
        ];
    }

    public function sarif(array $data): array
    {
        $runs = [];
        $byAnalyzer = collect($data['findings'])->groupBy('analyzer');
        foreach ($data['jobs'] as $job) {
            $results = $byAnalyzer->get($job['analyzer'], collect());
            $rules = $results->unique('rule_id')->map(fn ($f) => [
                'id' => $f['rule_id'],
                'shortDescription' => ['text' => $f['title']],
                'help' => ['text' => (string) ($f['remediation'] ?? '')],
                'properties' => array_filter(['tags' => array_values(array_filter([$f['category'], $f['cwe']]))]),
            ])->values()->all();
            $runs[] = [
                'tool' => ['driver' => [
                    'name' => $job['analyzer'],
                    'version' => (string) ($job['analyzer_version'] ?? 'unknown'),
                    'informationUri' => 'https://vulnix.local/analyzers/'.$job['analyzer'],
                    'rules' => $rules,
                ]],
                'invocations' => [[
                    'executionSuccessful' => $job['status'] === 'SUCCEEDED',
                    'exitCode' => $job['exit_code'],
                    'properties' => ['vulnixStatus' => $job['status'], 'errorType' => $job['error_type']],
                ]],
                'results' => $results->map(fn ($f) => array_filter([
                    'ruleId' => $f['rule_id'],
                    'level' => Severity::from($f['severity'])->sarifLevel(),
                    'message' => ['text' => $f['title'].'. '.$f['description']],
                    'locations' => $f['location']['file'] ? [[
                        'physicalLocation' => [
                            'artifactLocation' => ['uri' => $f['location']['file']],
                            'region' => array_filter(['startLine' => $f['location']['line'], 'endLine' => $f['location']['end_line']]),
                        ],
                    ]] : null,
                    'partialFingerprints' => ['vulnixFingerprint/v1' => $f['fingerprint']],
                    'properties' => ['severity' => $f['severity'], 'confidence' => $f['confidence'], 'cwe' => $f['cwe']],
                ], fn ($v) => $v !== null))->values()->all(),
                'properties' => [
                    'artifactSha256' => $data['artifact']['sha256'],
                    'analysisId' => $data['analysis']['id'],
                    'policySha256' => $data['policy']['sha256'],
                ],
            ];
        }

        return [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => $runs,
        ];
    }

    public function html(array $data): string
    {
        return view('reports.analysis', ['r' => $data, 'integrity' => Canonical::sha256($data['findings'])])->render();
    }

    private function pdf(array $data): string
    {
        $options = new Options;
        $options->setIsRemoteEnabled(false);      // nunca descargar recursos externos
        $options->setIsPhpEnabled(false);
        $options->setIsJavascriptEnabled(false);
        $options->setChroot([resource_path('views/reports')]);
        $options->setDefaultFont('DejaVu Sans');
        $pdf = new Dompdf($options);
        $pdf->loadHtml($this->html($data + ['pdf' => true]));
        $pdf->setPaper('A4');
        $pdf->render();

        return (string) $pdf->output();
    }
}
