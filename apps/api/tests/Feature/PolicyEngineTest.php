<?php

namespace Tests\Feature;

use App\Enums\DecisionResult;
use App\Enums\Role;
use App\Exceptions\VulnixException;
use App\Models\Analysis;
use App\Models\FindingException;
use App\Services\AnalysisPlanner;
use App\Services\DecisionService;
use App\Services\Policy\PolicyEngine;
use App\Support\DataStore;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/** Gate (manual §7 y §9): precedencia fail closed INCONCLUSIVE > REVIEW_REQUIRED > REJECTED > APPROVED. */
class PolicyEngineTest extends TestCase
{
    private function analysis(string $profile = 'web-development'): Analysis
    {
        $this->activePolicy($profile);
        $dev = $this->user(Role::Developer);
        $version = $this->version($dev);

        return app(AnalysisPlanner::class)->plan($version, $profile, [], $dev);
    }

    private function codes(array $evaluation): array
    {
        return array_column($evaluation['reasons'], 'code');
    }

    private function evaluate(Analysis $a): array
    {
        return app(PolicyEngine::class)->evaluate($a->fresh(['version', 'policy']));
    }

    public function test_full_compliance_is_approved(): void
    {
        $a = $this->analysis();
        $this->completeJobs($a);
        $r = $this->evaluate($a);
        $this->assertSame(DecisionResult::Approved, $r['result'], json_encode($r['reasons']));
    }

    public function test_failed_or_skipped_mandatory_control_is_inconclusive(): void
    {
        foreach (['FAILED', 'SKIPPED', 'TIMED_OUT'] as $status) {
            $a = $this->analysis();
            $this->completeJobs($a, ['vulnix-sast' => $status]);
            $r = $this->evaluate($a);
            $this->assertSame(DecisionResult::Inconclusive, $r['result'], $status);
            $this->assertContains('REQUIRED_CONTROL_NOT_EXECUTED', $this->codes($r));
        }
    }

    public function test_strict_profile_without_dast_or_tests_is_inconclusive(): void
    {
        $a = $this->analysis('web-production-strict');
        $this->completeJobs($a, ['vulnix-dast' => 'FAILED']);
        $r = $this->evaluate($a);
        $this->assertSame(DecisionResult::Inconclusive, $r['result']);
        $this->assertContains('TESTS_NOT_EXECUTED', $this->codes($r));
        $this->assertContains('COVERAGE_UNKNOWN', $this->codes($r));
    }

    public function test_tampered_or_missing_evidence_is_inconclusive(): void
    {
        $a = $this->analysis();
        $this->completeJobs($a);
        $ev = DB::table('evaluation.evidences')->whereIn('job_id', $a->jobs()->pluck('id'))->first();
        $path = app(DataStore::class)->path($ev->uri);
        chmod($path, 0644);
        file_put_contents($path, '{"tampered":true}');
        $r = $this->evaluate($a);
        $this->assertSame(DecisionResult::Inconclusive, $r['result']);
        $this->assertContains('EVIDENCE_TAMPERED', $this->codes($r));
    }

    public function test_changed_artifact_on_disk_is_inconclusive(): void
    {
        $a = $this->analysis();
        $this->completeJobs($a);
        $path = app(DataStore::class)->path($a->version->uri);
        chmod($path, 0644);
        file_put_contents($path, 'PK-modified');
        $r = $this->evaluate($a);
        $this->assertSame(DecisionResult::Inconclusive, $r['result']);
        $this->assertContains('ARTIFACT_INTEGRITY', $this->codes($r));
    }

    public function test_stale_intelligence_is_inconclusive(): void
    {
        $a = $this->analysis();
        $this->completeJobs($a, [], ['vulnix-sca' => ['components' => 12, 'intel' => ['ecosystems' => ['npm' => ['imported_at' => now()->subDays(30)->toIso8601String()]]]]]);
        $r = $this->evaluate($a);
        $this->assertSame(DecisionResult::Inconclusive, $r['result']);
        $this->assertContains('INTEL_STALE', $this->codes($r));
    }

    public function test_confirmed_high_finding_is_rejected(): void
    {
        $a = $this->analysis();
        $this->completeJobs($a);
        $this->addFinding($a, 'sast', 'HIGH', 'HIGH');
        $r = $this->evaluate($a);
        $this->assertSame(DecisionResult::Rejected, $r['result']);
        $this->assertContains('HIGH_FINDINGS', $this->codes($r));
    }

    public function test_exposed_secret_is_rejected(): void
    {
        $a = $this->analysis();
        $this->completeJobs($a);
        $this->addFinding($a, 'secrets', 'HIGH', 'MEDIUM', ['cwe' => 'CWE-798']);
        $this->assertContains('EXPOSED_SECRETS', $this->codes($this->evaluate($a)));
    }

    public function test_uncertain_high_finding_requires_human_review(): void
    {
        $a = $this->analysis();
        $this->completeJobs($a);
        $this->addFinding($a, 'sast', 'HIGH', 'LOW');
        $r = $this->evaluate($a);
        $this->assertSame(DecisionResult::ReviewRequired, $r['result']);
        $this->assertContains('UNCERTAIN_FINDINGS', $this->codes($r));
    }

    public function test_pending_exception_requires_review_and_approved_exception_unblocks_until_expiry(): void
    {
        $a = $this->analysis();
        $this->completeJobs($a);
        $findingId = $this->addFinding($a, 'sast', 'CRITICAL', 'HIGH');
        $requester = $this->user(Role::Developer);
        $ex = FindingException::create(['finding_id' => $findingId, 'requested_by' => $requester->id, 'kind' => 'ACCEPTED_RISK',
            'reason' => 'Mitigado por WAF interno en el segmento de laboratorio.', 'expires_at' => now()->addDays(10), 'status' => 'PENDING']);
        $this->assertSame(DecisionResult::ReviewRequired, $this->evaluate($a)['result']);

        $ex->forceFill(['status' => 'APPROVED', 'approver_id' => $this->user(Role::Approver)->id, 'decided_at' => now()])->save();
        $this->assertSame(DecisionResult::Approved, $this->evaluate($a)['result']);

        $this->travel(11)->days();
        $this->assertSame(DecisionResult::Rejected, $this->evaluate($a)['result'], 'una excepción vencida deja de cubrir el hallazgo');
    }

    public function test_build_failure_is_rejected_and_unverified_build_is_inconclusive(): void
    {
        $a = $this->analysis();
        $this->completeJobs($a, [], ['vulnix-quality' => ['build' => ['executed' => true, 'passed' => false, 'errors' => 2]]]);
        $this->assertContains('BUILD_FAILED', $this->codes($this->evaluate($a)));

        $b = $this->analysis();
        $this->completeJobs($b, [], ['vulnix-quality' => ['build' => ['executed' => true, 'passed' => null]]]);
        $r = $this->evaluate($b);
        $this->assertSame(DecisionResult::Inconclusive, $r['result']);
        $this->assertContains('BUILD_NOT_VERIFIED', $this->codes($r));
    }

    public function test_inconclusive_has_precedence_over_rejection(): void
    {
        $a = $this->analysis();
        $this->completeJobs($a, ['vulnix-secrets' => 'FAILED']);
        $this->addFinding($a, 'sast', 'CRITICAL', 'HIGH');
        $r = $this->evaluate($a);
        $this->assertSame(DecisionResult::Inconclusive, $r['result']);
        $this->assertContains('CRITICAL_FINDINGS', $this->codes($r), 'todas las razones quedan registradas');
    }

    public function test_running_analysis_cannot_be_decided(): void
    {
        $a = $this->analysis();
        $this->expectException(VulnixException::class);
        $this->evaluate($a);
    }

    public function test_decision_is_signed_bound_to_artifact_and_moves_analysis_to_completed(): void
    {
        $a = $this->analysis();
        $this->completeJobs($a);
        $decision = app(DecisionService::class)->decide($a, null, 'SERVICE');
        $this->assertSame('APPROVED', $decision->result->value);
        $this->assertSame('COMPLETED', $a->fresh()->status->value);
        $this->assertSame($a->artifact_sha256, $decision->artifact_sha256);
    }
}
