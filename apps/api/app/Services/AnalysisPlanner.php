<?php

namespace App\Services;

use App\Enums\AnalysisStatus;
use App\Exceptions\VulnixException;
use App\Models\Analysis;
use App\Models\Policy;
use App\Models\ProjectVersion;
use App\Models\ScanJob;
use App\Models\User;
use App\Support\Audit;
use App\Support\DataStore;
use Illuminate\Support\Facades\DB;

/**
 * Crea el plan de ejecución (manual §2): CREATED -> VALIDATING -> QUEUED, con un job por analizador.
 * Los jobs son idempotentes: idempotency_key = sha256(analysis_id|analyzer|policy_sha256|attempt).
 */
final class AnalysisPlanner
{
    public function __construct(private readonly DataStore $store) {}

    public function plan(ProjectVersion $version, string $profile, array $dynamic, User $actor, ?string $clientKey = null): Analysis
    {
        if ($clientKey !== null) {
            $existing = Analysis::query()->where('requested_by', $actor->id)->where('client_request_key', $clientKey)->first();
            if ($existing) {
                if ($existing->version_id !== $version->id || $existing->profile !== $profile) {
                    throw VulnixException::conflict('IDEMPOTENCY_KEY_REUSED', 'La clave de idempotencia ya se usó con otros parámetros.');
                }

                return $existing;
            }
        }

        $policy = Policy::activeFor($profile);
        if (! $policy) {
            throw new VulnixException('PROFILE_NOT_ACTIVE', "No existe una política activa y aprobada para el perfil \"{$profile}\".", 422);
        }

        $dynamicEnabled = (bool) ($dynamic['enabled'] ?? false);
        if ($dynamicEnabled) {
            $target = (string) ($dynamic['target_url'] ?? '');
            if (! in_array($target, config('vulnix.dast_allowed_targets'), true)) {
                throw new VulnixException('DAST_TARGET_NOT_AUTHORIZED',
                    'Las pruebas dinámicas solo pueden apuntar a destinos de laboratorio autorizados.', 422);
            }
        }

        return DB::transaction(function () use ($version, $profile, $policy, $dynamicEnabled, $dynamic, $actor, $clientKey) {
            $analysis = Analysis::create([
                'version_id' => $version->id,
                'policy_id' => $policy->id,
                'profile' => $profile,
                'status' => AnalysisStatus::Created->value,
                'artifact_sha256' => $version->sha256,
                'dynamic_testing' => $dynamicEnabled
                    ? ['enabled' => true, 'target_url' => $dynamic['target_url']]
                    : ['enabled' => false],
                'requested_by' => $actor->id,
                'client_request_key' => $clientKey,
            ]);
            $analysis->refresh();

            // VALIDATING: el artefacto debe existir y conservar exactamente su hash.
            $analysis->transitionTo(AnalysisStatus::Validating);
            $actual = $this->store->sha256($version->uri);
            if ($actual !== $version->sha256) {
                $analysis->transitionTo(AnalysisStatus::Failed, 'ARTIFACT_INTEGRITY: el artefacto no existe o su hash cambió.');
                Audit::log('analysis.validation_failed', 'analysis', $analysis->id, ['expected' => $version->sha256, 'actual' => $actual], $actor);

                return $analysis;
            }

            foreach ($this->jobsFor($policy->rules_json, $dynamicEnabled) as $job) {
                ScanJob::create([
                    'analysis_id' => $analysis->id,
                    'analyzer_name' => $job['analyzer'],
                    'category' => $job['category'],
                    'mandatory' => $job['mandatory'],
                    'attempt' => 1,
                    'max_attempts' => 2,
                    'status' => 'QUEUED',
                    'idempotency_key' => hash('sha256', implode('|', [$analysis->id, $job['analyzer'], $policy->sha256, 1])),
                    'metadata' => [],
                ]);
            }
            $analysis->transitionTo(AnalysisStatus::Queued);

            Audit::log('analysis.requested', 'analysis', $analysis->id, [
                'version_id' => $version->id, 'artifact_sha256' => $version->sha256,
                'profile' => $profile, 'policy_id' => $policy->id, 'policy_sha256' => $policy->sha256,
                'dynamic_testing' => $dynamicEnabled,
            ], $actor);

            return $analysis;
        });
    }

    /** @return list<array{analyzer:string, category:string, mandatory:bool}> */
    public function jobsFor(array $rules, bool $dynamicEnabled): array
    {
        $jobs = [];
        foreach ($rules['required'] as $category) {
            foreach ($rules['analyzers'][$category] as $name) {
                $jobs[$name] = ['analyzer' => $name, 'category' => $category, 'mandatory' => true];
            }
        }
        $catalog = ['semgrep' => 'sast', 'gitleaks' => 'secrets', 'vulnix-dast' => 'dast'];
        foreach ($rules['optional_analyzers'] as $name) {
            if (! isset($jobs[$name])) {
                $jobs[$name] = ['analyzer' => $name, 'category' => $catalog[$name] ?? 'sast', 'mandatory' => false];
            }
        }
        if ($dynamicEnabled && ! in_array('dast', $rules['required'], true)) {
            $jobs['vulnix-dast'] = ['analyzer' => 'vulnix-dast', 'category' => 'dast', 'mandatory' => false];
        }

        return array_values($jobs);
    }
}
