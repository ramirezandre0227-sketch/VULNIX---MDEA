<?php

namespace Tests\Feature;

use App\Enums\Role;
use App\Models\FindingException;
use App\Models\User;
use App\Services\AnalysisPlanner;
use App\Services\DecisionService;
use Illuminate\Database\QueryException;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\DB;
use Laravel\Sanctum\Sanctum;
use Tests\TestCase;
use ZipArchive;

/** Seguridad: ingesta adversarial, autenticación, RBAC, segregación de funciones e inmutabilidad. */
class SecurityTest extends TestCase
{
    private function upload(UploadedFile $file, ?User $user = null)
    {
        $this->activePolicy();
        $user ??= $this->user(Role::Developer);
        Sanctum::actingAs($user);
        $project = $this->project($user);

        return $this->post("/api/v1/projects/{$project->id}/versions", ['version' => '1.0.0', 'file' => $file], ['Accept' => 'application/json']);
    }

    // ------------------------------------------------------------------ ingesta (manual §8)
    public function test_rejects_zip_slip(): void
    {
        $this->upload($this->zipUpload(['../../evil.php' => '<?php system($_GET[1]);']))
            ->assertStatus(422)->assertJsonPath('error.code', 'ZIP_PATH_TRAVERSAL');
    }

    public function test_rejects_absolute_paths_and_reserved_names(): void
    {
        $this->upload($this->zipUpload(['/etc/cron.d/x' => 'x']))->assertStatus(422);
        $this->upload($this->zipUpload(['dir/CON.php' => 'x']))->assertStatus(422)->assertJsonPath('error.code', 'ZIP_PATH_INVALID');
    }

    public function test_rejects_symlinks(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'vxs');
        $zip = new ZipArchive;
        $zip->open($path, ZipArchive::OVERWRITE);
        $zip->addFromString('link', '/etc/passwd');
        $zip->setExternalAttributesName('link', ZipArchive::OPSYS_UNIX, (0120777 << 16));
        $zip->close();
        $this->upload(new UploadedFile($path, 'a.zip', 'application/zip', null, true))
            ->assertStatus(422)->assertJsonPath('error.code', 'ZIP_SPECIAL_ENTRY');
    }

    public function test_rejects_zip_bomb(): void
    {
        $this->upload($this->zipUpload(['bomb.txt' => str_repeat("\0", 30 * 1024 * 1024)]))
            ->assertStatus(422)->assertJsonPath('error.code', 'ZIP_BOMB_SUSPECTED');
    }

    public function test_rejects_binary_non_zip_and_duplicate_versions(): void
    {
        $bin = tempnam(sys_get_temp_dir(), 'vxb');
        file_put_contents($bin, "MZ\0\0binary");
        $this->upload(new UploadedFile($bin, 'tool.exe', 'application/octet-stream', null, true))
            ->assertStatus(422)->assertJsonPath('error.code', 'UPLOAD_TYPE_NOT_ALLOWED');

        $dev = $this->user(Role::Developer);
        Sanctum::actingAs($dev);
        $project = $this->project($dev);
        $this->post("/api/v1/projects/{$project->id}/versions", ['version' => '2.0.0', 'file' => $this->zipUpload(['a.php' => '<?php'])], ['Accept' => 'application/json'])->assertCreated();
        $this->post("/api/v1/projects/{$project->id}/versions", ['version' => '2.0.0', 'file' => $this->zipUpload(['b.php' => '<?php'])], ['Accept' => 'application/json'])
            ->assertStatus(409)->assertJsonPath('error.code', 'VERSION_EXISTS');
    }

    // ------------------------------------------------------------------ autenticación
    public function test_login_issues_token_and_locks_after_repeated_failures(): void
    {
        $user = $this->user(Role::Developer, 'ana.dev');
        $this->postJson('/api/v1/auth/login', ['username' => 'ana.dev', 'password' => 'Correct-Horse-9-Battery'])
            ->assertOk()->assertJsonPath('mode', 'token')->assertJsonStructure(['token', 'expires_at']);
        for ($i = 0; $i < 5; $i++) {
            $this->postJson('/api/v1/auth/login', ['username' => 'ana.dev', 'password' => 'mala'])->assertStatus(401);
        }
        $this->postJson('/api/v1/auth/login', ['username' => 'ana.dev', 'password' => 'Correct-Horse-9-Battery'])
            ->assertStatus(423)->assertJsonPath('error.code', 'ACCOUNT_LOCKED');
        $this->assertTrue($user->fresh()->isLocked());
    }

    public function test_unauthenticated_requests_get_stable_error_code(): void
    {
        $this->getJson('/api/v1/projects')->assertStatus(401)->assertJsonPath('error.code', 'UNAUTHENTICATED');
    }

    // ------------------------------------------------------------------ RBAC y segregación
    public function test_rbac_capabilities(): void
    {
        $this->activePolicy();
        Sanctum::actingAs($this->user(Role::Developer));
        $this->postJson('/api/v1/policies', ['yaml' => 'x'])->assertForbidden()->assertJsonPath('error.code', 'FORBIDDEN');
        $this->getJson('/api/v1/audit-logs')->assertForbidden();

        Sanctum::actingAs($this->user(Role::Auditor));
        $this->postJson('/api/v1/projects', ['name' => 'X', 'criticality' => 'LOW'])->assertForbidden();
        $this->getJson('/api/v1/audit-logs')->assertOk();
        $this->getJson('/api/v1/audit-logs/verify')->assertOk()->assertJsonPath('data.valid', true);
    }

    public function test_developers_cannot_see_other_projects(): void
    {
        $owner = $this->user(Role::Developer);
        $project = $this->project($owner);
        Sanctum::actingAs($this->user(Role::Developer));
        $this->getJson("/api/v1/projects/{$project->id}")->assertNotFound();
        Sanctum::actingAs($this->user(Role::SecurityReviewer));
        $this->getJson("/api/v1/projects/{$project->id}")->assertOk();
    }

    public function test_policy_author_cannot_approve_and_fail_open_policies_are_rejected(): void
    {
        $reviewer = $this->user(Role::SecurityReviewer);
        Sanctum::actingAs($reviewer);
        $yaml = file_get_contents(config('vulnix.policies_dir').'/web-development.yaml');
        $this->postJson('/api/v1/policies', ['yaml' => str_replace('fail_closed: true', 'fail_closed: false', $yaml)])
            ->assertStatus(422)->assertJsonPath('error.code', 'POLICY_INVALID');
        $policy = $this->postJson('/api/v1/policies', ['yaml' => str_replace('version: 1.0', 'version: 1.1', $yaml)])
            ->assertCreated()->assertJsonPath('data.version', '1.1')->assertJsonPath('data.status', 'DRAFT')->json('data');

        $approver = $this->user(Role::Approver);
        $policyModel = \App\Models\Policy::find($policy['id']);
        $policyModel->forceFill(['created_by' => $approver->id])->save();
        Sanctum::actingAs($approver);
        $this->postJson("/api/v1/policies/{$policy['id']}/approve")->assertForbidden();
        $policyModel->forceFill(['created_by' => $reviewer->id])->save();
        $this->postJson("/api/v1/policies/{$policy['id']}/approve")->assertOk()->assertJsonPath('data.status', 'ACTIVE');
    }

    public function test_exception_workflow_enforces_segregation_and_max_duration(): void
    {
        $this->activePolicy();
        $dev = $this->user(Role::Developer);
        $analysis = app(AnalysisPlanner::class)->plan($this->version($dev), 'web-development', [], $dev);
        $this->completeJobs($analysis);
        $findingId = $this->addFinding($analysis, 'sast', 'HIGH', 'HIGH');

        Sanctum::actingAs($dev);
        $this->postJson('/api/v1/exceptions', ['finding_id' => $findingId, 'kind' => 'FALSE_POSITIVE', 'reason' => 'Valor validado por lista blanca previa en el middleware.',
            'expires_at' => now()->addDays(365)->toIso8601String()])->assertStatus(422);
        $ex = $this->postJson('/api/v1/exceptions', ['finding_id' => $findingId, 'kind' => 'FALSE_POSITIVE', 'reason' => 'Valor validado por lista blanca previa en el middleware.',
            'expires_at' => now()->addDays(30)->toIso8601String()])->assertCreated()->json('data');
        $this->postJson("/api/v1/exceptions/{$ex['id']}/decision", ['decision' => 'APPROVE', 'note' => 'ok'])->assertForbidden();

        Sanctum::actingAs($this->user(Role::Approver));
        $this->postJson("/api/v1/exceptions/{$ex['id']}/decision", ['decision' => 'APPROVE', 'note' => 'Revisado: falso positivo.'])
            ->assertOk()->assertJsonPath('data.status', 'APPROVED');

        $decision = app(DecisionService::class)->decide($analysis->fresh(), null, 'SERVICE');
        $this->assertSame('APPROVED', $decision->result->value);
        $this->assertSame(1, $decision->reason_json['summary']['covered_by_exceptions']);
        $this->assertSame('FINDING_EXCEPTION_IMMUTABLE_RAW', $this->rawFindingUntouched($findingId));
    }

    private function rawFindingUntouched(string $findingId): string
    {
        $row = DB::table('evaluation.findings')->where('id', $findingId)->first();

        return $row->severity === 'HIGH' && $row->status === 'OPEN' ? 'FINDING_EXCEPTION_IMMUTABLE_RAW' : 'MODIFIED';
    }

    // ------------------------------------------------------------------ inmutabilidad (triggers)
    public function test_database_enforces_immutability_and_state_machine(): void
    {
        $this->activePolicy();
        $dev = $this->user(Role::Developer);
        $analysis = app(AnalysisPlanner::class)->plan($this->version($dev), 'web-development', [], $dev);
        $this->completeJobs($analysis);
        $decision = app(DecisionService::class)->decide($analysis, null, 'SERVICE');

        $attempts = [
            'audit update' => fn () => DB::table('audit.audit_logs')->update(['action' => 'x']),
            'audit delete' => fn () => DB::table('audit.audit_logs')->delete(),
            'decision update' => fn () => DB::table('evaluation.decisions')->where('id', $decision->id)->update(['result' => 'APPROVED']),
            'artifact hash change' => fn () => DB::table('catalog.project_versions')->where('id', $analysis->version_id)->update(['sha256' => str_repeat('0', 64)]),
            'invalid transition' => fn () => DB::table('evaluation.analyses')->where('id', $analysis->id)->update(['status' => 'RUNNING']),
            'policy content' => fn () => DB::table('catalog.policies')->where('id', $analysis->policy_id)->update(['rules_json' => '{}']),
        ];
        foreach ($attempts as $label => $attempt) {
            try {
                DB::transaction($attempt);
                $this->fail("Se permitió: {$label}");
            } catch (QueryException $e) {
                $this->assertMatchesRegularExpression('/VULNIX_(IMMUTABLE|INVALID_TRANSITION)/', $e->getMessage(), $label);
            }
        }
        $this->artisan('vulnix:audit:verify')->assertSuccessful();
    }

    public function test_security_headers_are_present(): void
    {
        $this->get('/up')->assertHeader('X-Content-Type-Options', 'nosniff')->assertHeader('X-Frame-Options', 'DENY')
            ->assertHeader('Content-Security-Policy');
    }
}
