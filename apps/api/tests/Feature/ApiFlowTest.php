<?php

namespace Tests\Feature;

use App\Enums\Role;
use App\Models\Analysis;
use App\Services\Signing\DecisionSigner;
use App\Support\DataStore;
use Laravel\Sanctum\Sanctum;
use Tests\TestCase;

/** Integración API: carga ZIP -> análisis -> (orquestador) -> decisión firmada -> verificación del gate. */
class ApiFlowTest extends TestCase
{
    public function test_full_flow_and_deployment_gate_blocks_on_hash_change(): void
    {
        $this->activePolicy('web-development');
        $dev = $this->user(Role::Developer);
        Sanctum::actingAs($dev);

        $project = $this->postJson('/api/v1/projects', ['name' => 'Tienda', 'criticality' => 'HIGH', 'default_profile' => 'web-development'])
            ->assertCreated()->json('data');

        $upload = $this->zipUpload(['index.php' => "<?php echo 'ok';\n", 'package.json' => '{}']);
        $expectedSha = hash_file('sha256', $upload->getRealPath());
        $version = $this->post("/api/v1/projects/{$project['id']}/versions", ['version' => '1.0.0', 'file' => $upload], ['Accept' => 'application/json'])
            ->assertCreated()->json('data');
        $this->assertSame($expectedSha, $version['sha256']);
        $this->assertSame('php', $version['technologies']['primary_language']);

        $res = $this->postJson('/api/v1/analyses', ['project_version_id' => $version['id']], ['Idempotency-Key' => 'ci-run-000001'])
            ->assertStatus(202)->assertJsonPath('status', 'QUEUED');
        $again = $this->postJson('/api/v1/analyses', ['project_version_id' => $version['id']], ['Idempotency-Key' => 'ci-run-000001']);
        $this->assertSame($res->json('analysis_id'), $again->json('analysis_id'), 'Idempotency-Key devuelve el mismo análisis');

        $analysis = Analysis::findOrFail($res->json('analysis_id'));
        $this->getJson("/api/v1/analyses/{$analysis->id}")->assertOk()->assertJsonCount(6, 'data.jobs');
        $this->postJson("/api/v1/analyses/{$analysis->id}/evaluate")->assertStatus(409)->assertJsonPath('error.code', 'ANALYSIS_NOT_READY');

        $this->completeJobs($analysis);
        $this->postJson("/api/v1/analyses/{$analysis->id}/evaluate")->assertCreated()->assertJsonPath('data.result', 'APPROVED');

        $token = $this->get("/api/v1/analyses/{$analysis->id}/decision/token")->assertOk()->getContent();
        $signer = app(DecisionSigner::class);
        $artifact = app(DataStore::class)->path($analysis->version->uri);

        $this->assertTrue($signer->verify($token, hash_file('sha256', $artifact))['valid']);
        $tampered = $signer->verify($token, hash('sha256', file_get_contents($artifact).'x'));
        $this->assertFalse($tampered['valid']);
        $this->assertContains('ARTIFACT_HASH_MISMATCH', $tampered['errors'], 'un cambio de hash invalida la autorización');

        $this->postJson('/api/v1/authorization/verify', ['token' => $token, 'artifact_sha256' => str_repeat('0', 64)])
            ->assertStatus(422)->assertJsonPath('data.valid', false);

        foreach (['json', 'sarif', 'html', 'pdf'] as $format) {
            $resp = $this->get("/api/v1/analyses/{$analysis->id}/report?format={$format}")->assertOk();
            $this->assertSame(hash('sha256', $resp->getContent()), $resp->headers->get('X-Vulnix-SHA256'));
        }
        $sarif = json_decode($this->get("/api/v1/analyses/{$analysis->id}/report?format=sarif")->getContent(), true);
        $this->assertSame('2.1.0', $sarif['version']);
        $this->assertCount(6, $sarif['runs']);
    }

    public function test_internal_api_requires_service_token(): void
    {
        $this->postJson('/internal/v1/analyses/'.fake()->uuid().'/evaluate')->assertStatus(401)->assertJsonPath('error.code', 'SERVICE_UNAUTHENTICATED');
        $this->postJson('/internal/v1/analyses/'.fake()->uuid().'/evaluate', [], ['X-Vulnix-Service-Token' => config('vulnix.internal_token')])
            ->assertStatus(404);
    }

    public function test_internal_evaluation_by_orchestrator(): void
    {
        $this->activePolicy('web-development');
        $dev = $this->user(Role::Developer);
        $analysis = app(\App\Services\AnalysisPlanner::class)->plan($this->version($dev), 'web-development', [], $dev);
        $this->completeJobs($analysis);
        $this->postJson("/internal/v1/analyses/{$analysis->id}/evaluate", [], ['X-Vulnix-Service-Token' => config('vulnix.internal_token')])
            ->assertCreated()->assertJsonPath('result', 'APPROVED');
        $this->assertSame('SERVICE', $analysis->decisions()->first()->issued_via);
    }

    public function test_dast_requires_authorized_lab_target(): void
    {
        $this->activePolicy('web-development');
        $dev = $this->user(Role::Developer);
        Sanctum::actingAs($dev);
        $v = $this->version($dev);
        $this->postJson('/api/v1/analyses', ['project_version_id' => $v->id, 'dynamic_testing' => ['enabled' => true, 'target_url' => 'https://produccion.example.com']])
            ->assertStatus(422)->assertJsonPath('error.code', 'DAST_TARGET_NOT_AUTHORIZED');
    }
}
