<?php

namespace Tests\Feature;

use App\Enums\Role;
use App\Models\FindingException;
use App\Models\User;
use App\Services\AnalysisPlanner;
use Laravel\Sanctum\Sanctum;
use Tests\TestCase;

class SuperadminTest extends TestCase
{
    public function test_superadmin_has_every_ability_of_every_role(): void
    {
        foreach (Role::cases() as $role) {
            foreach ($role->abilities() as $ability) {
                $this->assertTrue(Role::Superadmin->can($ability), "{$role->value}: {$ability}");
            }
        }
    }

    public function test_cli_creates_superadmin_with_spaced_username_and_case_insensitive_login(): void
    {
        $this->artisan('vulnix:user:create', ['username' => 'Usuario Prueba', '--role' => 'superadmin',
            '--name' => 'Nombre Con Tildes Ñandú', '--password' => 'Prueba123x', '--allow-short-password' => true])->assertSuccessful();
        $user = User::where('username', 'usuario prueba')->firstOrFail();
        $this->assertSame(Role::Superadmin, $user->role);

        $this->postJson('/api/v1/auth/login', ['username' => 'Usuario Prueba', 'password' => 'Prueba123x'])
            ->assertOk()->assertJsonPath('user.role', 'superadmin')->assertJsonPath('user.display_name', 'Nombre Con Tildes Ñandú');
    }

    public function test_short_password_requires_explicit_override(): void
    {
        $this->artisan('vulnix:user:create', ['username' => 'corto', '--password' => 'Prueba123x'])->assertFailed();
    }

    public function test_admin_cannot_create_or_modify_superadmins(): void
    {
        $super = $this->user(Role::Superadmin);
        Sanctum::actingAs($this->user(Role::Admin));
        $this->postJson('/api/v1/users', ['username' => 'otro super', 'display_name' => 'X', 'role' => 'superadmin', 'password' => 'Segura-Clave-2026'])
            ->assertForbidden();
        $this->patchJson("/api/v1/users/{$super->id}", ['active' => false])->assertForbidden();

        Sanctum::actingAs($super);
        $this->postJson('/api/v1/users', ['username' => 'Otro Super', 'display_name' => 'X', 'role' => 'superadmin', 'password' => 'Segura-Clave-2026'])
            ->assertCreated()->assertJsonPath('data.username', 'otro super');
    }

    public function test_superadmin_still_cannot_approve_own_exception(): void
    {
        $this->activePolicy();
        $super = $this->user(Role::Superadmin);
        $analysis = app(AnalysisPlanner::class)->plan($this->version($super), 'web-development', [], $super);
        $this->completeJobs($analysis);
        $ex = FindingException::create(['finding_id' => $this->addFinding($analysis, 'sast', 'HIGH', 'HIGH'), 'requested_by' => $super->id,
            'kind' => 'ACCEPTED_RISK', 'reason' => 'Riesgo aceptado temporalmente por el responsable.', 'expires_at' => now()->addDays(5), 'status' => 'PENDING']);
        Sanctum::actingAs($super);
        $this->postJson("/api/v1/exceptions/{$ex->id}/decision", ['decision' => 'APPROVE', 'note' => 'Autoaprobación'])->assertForbidden();
    }
}
