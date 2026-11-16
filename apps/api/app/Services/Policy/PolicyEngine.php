<?php

namespace App\Services\Policy;

use App\Enums\AnalysisStatus;
use App\Enums\DecisionResult;
use App\Enums\ExceptionStatus;
use App\Enums\JobStatus;
use App\Exceptions\VulnixException;
use App\Models\Analysis;
use App\Models\Evidence;
use App\Models\Finding;
use App\Models\FindingException;
use App\Support\Canonical;
use App\Support\DataStore;
use Carbon\CarbonImmutable;
use Illuminate\Support\Collection;

/**
 * Motor de políticas (manual §7). Precedencia estricta, fail closed:
 *   1. artefacto inválido, evidencia faltante, herramientas fallidas o inteligencia caducada -> INCONCLUSIVE
 *   2. excepciones pendientes o hallazgos inciertos que requieren revisión humana            -> REVIEW_REQUIRED
 *   3. controles obligatorios incumplidos                                                   -> REJECTED
 *   4. únicamente el cumplimiento integral                                                  -> APPROVED
 * Todas las razones se registran aunque una de mayor precedencia determine el resultado.
 */
final class PolicyEngine
{
    private const OUTCOME_RANK = ['INCONCLUSIVE' => 3, 'REVIEW_REQUIRED' => 2, 'REJECTED' => 1];

    public function __construct(private readonly DataStore $store) {}

    /** @return array{result: DecisionResult, reasons: list<array>, checks: list<array>, summary: array} */
    public function evaluate(Analysis $analysis, ?CarbonImmutable $now = null): array
    {
        $now ??= CarbonImmutable::now();
        if (! $analysis->status->isEvaluable()) {
            throw VulnixException::conflict('ANALYSIS_NOT_READY',
                'El análisis aún no ha terminado; no se puede emitir una decisión.', ['status' => $analysis->status->value]);
        }

        $policy = $analysis->policy;
        $rules = $policy->rules_json;
        $reasons = [];
        $checks = [];

        // ---------------------------------------------------------------- 1. Integridad
        if (in_array($analysis->status, [AnalysisStatus::Failed, AnalysisStatus::Cancelled, AnalysisStatus::TimedOut], true)) {
            $reasons[] = $this->reason('INCONCLUSIVE', 'ANALYSIS_NOT_COMPLETED',
                'El análisis no terminó correctamente.', ['status' => $analysis->status->value, 'detail' => $analysis->status_reason]);
        }

        $version = $analysis->version;
        $actualSha = $this->safeSha($version->uri);
        $artifactOk = $actualSha !== null && $actualSha === $analysis->artifact_sha256 && $version->sha256 === $analysis->artifact_sha256;
        $checks[] = ['control' => 'artifact_integrity', 'status' => $artifactOk ? 'PASS' : 'FAIL'];
        if (! $artifactOk) {
            $reasons[] = $this->reason('INCONCLUSIVE', 'ARTIFACT_INTEGRITY',
                'El artefacto no existe o su SHA-256 no coincide con el registrado.',
                ['expected' => $analysis->artifact_sha256, 'actual' => $actualSha]);
        }

        $policyOk = $policy->status !== 'DRAFT' && Canonical::sha256($rules) === $policy->sha256;
        $checks[] = ['control' => 'policy_integrity', 'status' => $policyOk ? 'PASS' : 'FAIL'];
        if (! $policyOk) {
            $reasons[] = $this->reason('INCONCLUSIVE', 'POLICY_INTEGRITY',
                'La política no está aprobada o su contenido no coincide con su hash.', ['policy_id' => $policy->id]);
        }

        // ---------------------------------------------------------------- 1b. Controles obligatorios y evidencia
        $jobs = $analysis->latestJobs();
        foreach ($rules['required'] as $category) {
            foreach ($rules['analyzers'][$category] as $analyzerName) {
                $job = $jobs->first(fn ($j) => $j->analyzer_name === $analyzerName && $j->category === $category);
                $control = "{$category}:{$analyzerName}";
                if (! $job) {
                    $reasons[] = $this->reason('INCONCLUSIVE', 'REQUIRED_CONTROL_MISSING',
                        "El control obligatorio {$control} no fue planificado.", ['control' => $control]);
                    $checks[] = ['control' => $control, 'status' => 'MISSING'];

                    continue;
                }
                if ($job->status !== JobStatus::Succeeded) {
                    // FAILED, TIMED_OUT, SKIPPED o CANCELLED nunca se interpretan como PASS.
                    $reasons[] = $this->reason('INCONCLUSIVE', 'REQUIRED_CONTROL_NOT_EXECUTED',
                        "El control obligatorio {$control} no se completó ({$job->status->value}).",
                        ['control' => $control, 'status' => $job->status->value, 'error_type' => $job->error_type]);
                    $checks[] = ['control' => $control, 'status' => $job->status->value];

                    continue;
                }
                $evidenceProblem = $this->checkJobEvidence($job);
                if ($evidenceProblem !== null) {
                    $reasons[] = $this->reason('INCONCLUSIVE', $evidenceProblem,
                        "La evidencia del control {$control} falta, está alterada o no registra la versión de la herramienta.",
                        ['control' => $control, 'job_id' => $job->id]);
                    $checks[] = ['control' => $control, 'status' => 'EVIDENCE_INVALID'];

                    continue;
                }
                $checks[] = ['control' => $control, 'status' => 'PASS', 'analyzer_version' => $job->analyzer?->version];
            }
        }

        // ---------------------------------------------------------------- 1c. Vigencia de la inteligencia
        if (in_array('sca', $rules['required'], true)) {
            $maxAge = (int) $rules['intelligence']['max_age_days'];
            foreach ($jobs->where('category', 'sca')->where('status', JobStatus::Succeeded) as $job) {
                $intel = $job->metadata['intel'] ?? null;
                $components = (int) ($job->metadata['components'] ?? 0);
                if ($components > 0 && ! is_array($intel['ecosystems'] ?? null)) {
                    $reasons[] = $this->reason('INCONCLUSIVE', 'INTEL_UNAVAILABLE',
                        'El análisis de composición no registra la inteligencia de vulnerabilidades utilizada.', ['job_id' => $job->id]);

                    continue;
                }
                foreach (($intel['ecosystems'] ?? []) as $ecosystem => $info) {
                    $importedAt = isset($info['imported_at']) ? CarbonImmutable::parse($info['imported_at']) : null;
                    $ageDays = $importedAt ? $importedAt->diffInDays($now) : null;
                    // Fechas futuras (reloj alterado o datos manipulados) también invalidan la frescura.
                    if ($ageDays === null || $ageDays > $maxAge || $ageDays < -1) {
                        $reasons[] = $this->reason('INCONCLUSIVE', 'INTEL_STALE',
                            "La inteligencia de vulnerabilidades de {$ecosystem} está caducada o no tiene fecha.",
                            ['ecosystem' => $ecosystem, 'age_days' => $ageDays !== null ? round($ageDays, 1) : null, 'max_age_days' => $maxAge]);
                    }
                }
            }
        }

        // ---------------------------------------------------------------- 2/3. Hallazgos y excepciones
        $findings = Finding::query()->where('analysis_id', $analysis->id)->get();
        $groups = $findings->groupBy(fn (Finding $f) => $f->correlation_key ?: $f->fingerprint);
        $coveringFingerprints = $this->effectiveExceptionFingerprints($analysis, $findings, $now);

        $pending = FindingException::query()->whereIn('finding_id', $findings->pluck('id'))
            ->where('status', ExceptionStatus::Pending->value)->count();
        if ($pending > 0) {
            $reasons[] = $this->reason('REVIEW_REQUIRED', 'EXCEPTION_PENDING',
                "Hay {$pending} excepción(es) pendiente(s) de aprobación.", ['count' => $pending]);
        }

        $sec = $rules['security'];
        $confirmedCritical = $confirmedHigh = $secrets = $uncertain = $covered = 0;
        $blockingSamples = [];
        foreach ($groups as $key => $group) {
            /** @var Collection<int, Finding> $group */
            $top = $group->sortByDesc(fn (Finding $f) => $f->severity->rank() * 10 + $this->confRank($f->confidence))->first();
            $isCovered = $group->contains(fn (Finding $f) => isset($coveringFingerprints[$f->fingerprint]));
            if ($isCovered) {
                $covered++;

                continue;
            }
            $severity = $top->severity->value;
            $confidence = $group->max(fn (Finding $f) => $this->confRank($f->confidence));
            $isSecret = $group->contains(fn (Finding $f) => $f->category === 'secrets');

            if ($isSecret && $sec['block_exposed_secrets']) {
                if ($confidence >= 2) {
                    $secrets++;
                    $blockingSamples[] = $this->sample($top);
                } elseif ($sec['review_uncertain_findings']) {
                    $uncertain++;
                }

                continue;
            }
            if (! in_array($severity, ['CRITICAL', 'HIGH'], true)) {
                continue;
            }
            if ($confidence >= 3) {
                $severity === 'CRITICAL' ? $confirmedCritical++ : $confirmedHigh++;
                $blockingSamples[] = $this->sample($top);
            } elseif ($sec['review_uncertain_findings']) {
                $uncertain++;
            }
        }

        if ($uncertain > 0) {
            $reasons[] = $this->reason('REVIEW_REQUIRED', 'UNCERTAIN_FINDINGS',
                "{$uncertain} hallazgo(s) crítico(s)/alto(s) de confianza no alta requieren revisión humana.", ['count' => $uncertain]);
        }
        if ($confirmedCritical > $sec['max_confirmed_critical']) {
            $reasons[] = $this->reason('REJECTED', 'CRITICAL_FINDINGS',
                "Hallazgos críticos confirmados: {$confirmedCritical} (máximo {$sec['max_confirmed_critical']}).",
                ['count' => $confirmedCritical, 'max' => $sec['max_confirmed_critical']]);
        }
        if ($confirmedHigh > $sec['max_confirmed_high']) {
            $reasons[] = $this->reason('REJECTED', 'HIGH_FINDINGS',
                "Hallazgos altos confirmados: {$confirmedHigh} (máximo {$sec['max_confirmed_high']}).",
                ['count' => $confirmedHigh, 'max' => $sec['max_confirmed_high']]);
        }
        if ($secrets > 0) {
            $reasons[] = $this->reason('REJECTED', 'EXPOSED_SECRETS',
                "Se detectaron {$secrets} secreto(s) expuesto(s) en el código.", ['count' => $secrets]);
        }

        // ---------------------------------------------------------------- 3b. Calidad
        $this->evaluateQuality($rules['quality'], $jobs, $reasons, $checks);

        // ---------------------------------------------------------------- Resultado
        $result = DecisionResult::Approved;
        $maxRank = 0;
        foreach ($reasons as $r) {
            $maxRank = max($maxRank, self::OUTCOME_RANK[$r['outcome']]);
        }
        $result = match ($maxRank) {
            3 => DecisionResult::Inconclusive,
            2 => DecisionResult::ReviewRequired,
            1 => DecisionResult::Rejected,
            default => $result,
        };

        $bySeverity = $findings->groupBy(fn (Finding $f) => $f->severity->value)->map->count();

        return [
            'result' => $result,
            'reasons' => $reasons,
            'checks' => $checks,
            'summary' => [
                'findings_total' => $findings->count(),
                'unique_issues' => $groups->count(),
                'by_severity' => $bySeverity->all(),
                'confirmed_critical' => $confirmedCritical,
                'confirmed_high' => $confirmedHigh,
                'exposed_secrets' => $secrets,
                'uncertain_requiring_review' => $uncertain,
                'covered_by_exceptions' => $covered,
                'pending_exceptions' => $pending,
                'blocking_samples' => array_slice($blockingSamples, 0, 10),
                'evaluated_at' => $now->toIso8601String(),
            ],
        ];
    }

    private function evaluateQuality(array $quality, Collection $jobs, array &$reasons, array &$checks): void
    {
        $qaJobs = $jobs->where('category', 'quality')->where('status', JobStatus::Succeeded);
        $meta = fn (string $key) => $qaJobs->map(fn ($j) => $j->metadata[$key] ?? null)->filter()->values();

        if ($quality['require_build_pass']) {
            $builds = $meta('build');
            if ($builds->isEmpty() || $builds->contains(fn ($b) => ($b['passed'] ?? null) === null)) {
                $reasons[] = $this->reason('INCONCLUSIVE', 'BUILD_NOT_VERIFIED', 'No hay evidencia de que la compilación/verificación sintáctica se haya ejecutado.');
                $checks[] = ['control' => 'quality:build', 'status' => 'NOT_VERIFIED'];
            } elseif ($builds->contains(fn ($b) => $b['passed'] === false)) {
                $reasons[] = $this->reason('REJECTED', 'BUILD_FAILED', 'La compilación/verificación sintáctica falló.',
                    ['errors' => $builds->sum(fn ($b) => (int) ($b['errors'] ?? 0))]);
                $checks[] = ['control' => 'quality:build', 'status' => 'FAIL'];
            } else {
                $checks[] = ['control' => 'quality:build', 'status' => 'PASS'];
            }
        }

        if ($quality['require_tests_pass']) {
            $tests = $meta('tests');
            if ($tests->isEmpty() || $tests->contains(fn ($t) => ($t['executed'] ?? false) !== true || ($t['passed'] ?? null) === null)) {
                $reasons[] = $this->reason('INCONCLUSIVE', 'TESTS_NOT_EXECUTED',
                    'La política exige pruebas, pero no hay evidencia de su ejecución (requiere sandbox de ejecución aislado).');
                $checks[] = ['control' => 'quality:tests', 'status' => 'NOT_EXECUTED'];
            } elseif ($tests->contains(fn ($t) => $t['passed'] === false)) {
                $reasons[] = $this->reason('REJECTED', 'TESTS_FAILED', 'Las pruebas del proyecto fallaron.');
                $checks[] = ['control' => 'quality:tests', 'status' => 'FAIL'];
            } else {
                $checks[] = ['control' => 'quality:tests', 'status' => 'PASS'];
            }
        }

        $min = $quality['min_line_coverage'];
        if ($min > 0) {
            $coverage = $meta('coverage')->map(fn ($c) => $c['line_pct'] ?? null)->filter(fn ($v) => $v !== null);
            if ($coverage->isEmpty()) {
                $reasons[] = $this->reason('INCONCLUSIVE', 'COVERAGE_UNKNOWN', "La política exige cobertura >= {$min}% y no hay medición.");
                $checks[] = ['control' => 'quality:coverage', 'status' => 'NOT_VERIFIED'];
            } elseif ($coverage->min() < $min) {
                $reasons[] = $this->reason('REJECTED', 'COVERAGE_BELOW_MIN', "Cobertura {$coverage->min()}% inferior al mínimo {$min}%.");
                $checks[] = ['control' => 'quality:coverage', 'status' => 'FAIL'];
            } else {
                $checks[] = ['control' => 'quality:coverage', 'status' => 'PASS'];
            }
        }
    }

    /** Devuelve null si la evidencia es válida, o el código del problema. */
    private function checkJobEvidence($job): ?string
    {
        if ($job->analyzer_id === null || $job->analyzer === null) {
            return 'TOOL_VERSION_UNKNOWN';
        }
        $evidences = Evidence::query()->where('job_id', $job->id)->whereNull('finding_id')->get();
        if ($evidences->where('kind', 'RAW_OUTPUT')->isEmpty()) {
            return 'EVIDENCE_MISSING';
        }
        foreach ($evidences as $evidence) {
            if ($this->safeSha($evidence->uri) !== $evidence->sha256) {
                return 'EVIDENCE_TAMPERED';
            }
        }

        return null;
    }

    /**
     * Huellas cubiertas por excepciones aprobadas y vigentes. Una excepción aprobada sobre la misma huella
     * en otra versión del mismo proyecto también aplica (hasta su vencimiento).
     *
     * @return array<string, true>
     */
    private function effectiveExceptionFingerprints(Analysis $analysis, Collection $findings, CarbonImmutable $now): array
    {
        if ($findings->isEmpty()) {
            return [];
        }
        $projectId = $analysis->version->project_id;
        $rows = FindingException::query()
            ->join('evaluation.findings as f', 'f.id', '=', 'evaluation.exceptions.finding_id')
            ->join('evaluation.analyses as a', 'a.id', '=', 'f.analysis_id')
            ->join('catalog.project_versions as v', 'v.id', '=', 'a.version_id')
            ->where('v.project_id', $projectId)
            ->where('evaluation.exceptions.status', ExceptionStatus::Approved->value)
            ->where('evaluation.exceptions.expires_at', '>', $now)
            ->whereIn('f.fingerprint', $findings->pluck('fingerprint')->unique())
            ->pluck('f.fingerprint');

        return $rows->mapWithKeys(fn ($fp) => [$fp => true])->all();
    }

    private function safeSha(string $uri): ?string
    {
        try {
            return $this->store->sha256($uri);
        } catch (VulnixException) {
            return null;
        }
    }

    private function confRank(string $confidence): int
    {
        return match ($confidence) { 'HIGH' => 3, 'MEDIUM' => 2, default => 1 };
    }

    private function sample(Finding $f): array
    {
        return ['finding_id' => $f->id, 'rule_id' => $f->rule_id, 'severity' => $f->severity->value,
            'file' => $f->file_path, 'line' => $f->start_line];
    }

    private function reason(string $outcome, string $code, string $message, array $details = []): array
    {
        return ['outcome' => $outcome, 'code' => $code, 'message' => $message, 'details' => $details];
    }
}
