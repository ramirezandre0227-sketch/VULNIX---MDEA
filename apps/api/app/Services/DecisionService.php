<?php

namespace App\Services;

use App\Enums\AnalysisStatus;
use App\Enums\DecisionResult;
use App\Models\Analysis;
use App\Models\Decision;
use App\Models\User;
use App\Services\Policy\PolicyEngine;
use App\Services\Signing\DecisionSigner;
use App\Support\Audit;
use App\Support\DataStore;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Emite decisiones firmadas ligadas al hash exacto del artefacto y de la política (manual §7).
 * Solo la API ejecuta este servicio: los workers no tienen acceso a la clave ni a la tabla de decisiones.
 */
final class DecisionService
{
    public function __construct(
        private readonly PolicyEngine $engine,
        private readonly DecisionSigner $signer,
        private readonly DataStore $store,
    ) {}

    public function decide(Analysis $analysis, ?User $actor, string $via = 'USER'): Decision
    {
        return DB::transaction(function () use ($analysis, $actor, $via) {
            /** @var Analysis $locked */
            $locked = Analysis::query()->whereKey($analysis->id)->lockForUpdate()->firstOrFail();
            $locked->load('version.project', 'policy');

            $now = CarbonImmutable::now();
            $evaluation = $this->engine->evaluate($locked, $now);
            $result = $evaluation['result'];

            $decisionId = (string) Str::uuid7();
            $expiresAt = $now->addHours(config('vulnix.authorization_ttl_hours'));
            $policy = $locked->policy;
            $claims = [
                'iss' => config('vulnix.issuer'),
                'sub' => $locked->id,
                'jti' => $decisionId,
                'iat' => $now->getTimestamp(),
                'exp' => $expiresAt->getTimestamp(),
                'issuer' => config('vulnix.issuer'),
                'decision_id' => $decisionId,
                'analysis_id' => $locked->id,
                'project_id' => $locked->version->project_id,
                'project_version' => $locked->version->version,
                'artifact_sha256' => $locked->artifact_sha256,
                'policy_code' => $policy->code,
                'policy_version' => $policy->version,
                'policy_sha256' => $policy->sha256,
                'result' => $result->value,
                'issued_at' => $now->toIso8601String(),
                'expires_at' => $expiresAt->toIso8601String(),
            ];
            $token = $this->signer->sign($claims);
            $stored = $this->store->putImmutable("decisions/{$locked->id}/{$decisionId}.jws", $token);

            $decision = Decision::create([
                'id' => $decisionId,
                'analysis_id' => $locked->id,
                'policy_id' => $policy->id,
                'result' => $result->value,
                'reason_json' => [
                    'reasons' => $evaluation['reasons'],
                    'checks' => $evaluation['checks'],
                    'summary' => $evaluation['summary'],
                ],
                'artifact_sha256' => $locked->artifact_sha256,
                'policy_sha256' => $policy->sha256,
                'signed_token_uri' => $stored['uri'],
                'token_sha256' => $stored['sha256'],
                'key_id' => $this->signer->keyId(),
                'issued_at' => $now,
                'expires_at' => $expiresAt,
                'issued_by' => $actor?->id,
                'issued_via' => $via,
            ]);

            if ($locked->status === AnalysisStatus::Evaluating) {
                $locked->transitionTo(
                    $result === DecisionResult::Inconclusive ? AnalysisStatus::Inconclusive : AnalysisStatus::Completed,
                    $result === DecisionResult::Inconclusive ? 'Evidencia incompleta: ver razones de la decisión.' : null,
                );
            }

            Audit::log('decision.issued', 'analysis', $locked->id, [
                'decision_id' => $decisionId,
                'result' => $result->value,
                'artifact_sha256' => $locked->artifact_sha256,
                'policy_sha256' => $policy->sha256,
                'reason_codes' => array_column($evaluation['reasons'], 'code'),
                'token_sha256' => $stored['sha256'],
            ], $actor, $actor ? 'USER' : 'SERVICE');

            return $decision;
        });
    }
}
