<?php

namespace App\Console\Commands;

use App\Enums\AnalysisStatus;
use App\Enums\Role;
use App\Http\Controllers\Api\AdminController;
use App\Models\Analysis;
use App\Models\Policy;
use App\Models\User;
use App\Services\DecisionService;
use App\Services\Policy\PolicyLoader;
use App\Services\Signing\DecisionSigner;
use App\Support\Audit;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Throwable;

/** Crea un usuario (uso típico: el primer administrador). */
class UserCreate extends Command
{
    protected $signature = 'vulnix:user:create {username} {--role=admin} {--name=} {--password= : Si se omite se genera una aleatoria}
        {--allow-short-password : Excepción explícita (auditada) a la longitud mínima de 12 caracteres; mínimo absoluto 8}';

    protected $description = 'Crea un usuario de VULNIX';

    public function handle(): int
    {
        $role = Role::tryFrom((string) $this->option('role'));
        $username = User::normalizeUsername((string) $this->argument('username'));
        if (! $role || ! User::validUsername($username)) {
            $this->error('Rol o nombre de usuario inválido. Roles: '.implode(', ', array_column(Role::cases(), 'value')));

            return self::FAILURE;
        }
        if (User::where('username', $username)->exists()) {
            $this->error('El usuario ya existe.');

            return self::FAILURE;
        }
        $password = (string) ($this->option('password') ?: rtrim(strtr(base64_encode(random_bytes(15)), '+/', 'Aa'), '=').'9z');
        $short = strlen($password) < 12;
        if ($short && (! $this->option('allow-short-password') || strlen($password) < 8)) {
            $this->error('La contraseña debe tener al menos 12 caracteres (o 8 con --allow-short-password).');

            return self::FAILURE;
        }
        if (! preg_match('/[a-z]/', $password) || ! preg_match('/[A-Z]/', $password) || ! preg_match('/\d/', $password)) {
            $this->error('La contraseña debe combinar mayúsculas, minúsculas y números.');

            return self::FAILURE;
        }
        $user = User::create([
            'username' => $username, 'display_name' => $this->option('name') ?: $username,
            'role' => $role->value, 'password_hash' => $password, 'active' => true,
        ]);
        Audit::log('user.created', 'user', $user->id, ['username' => $username, 'role' => $role->value, 'via' => 'cli',
            'password_policy_override' => $short], null, 'SYSTEM');
        if ($short) {
            $this->warn('Excepción a la política de contraseñas registrada en auditoría: se recomienda cambiarla por una de 12+ caracteres.');
        }
        $this->info("Usuario {$username} ({$role->value}) creado.");
        if (! $this->option('password')) {
            $this->warn("Contraseña generada (guárdela ahora, no se volverá a mostrar): {$password}");
        }

        return self::SUCCESS;
    }
}
