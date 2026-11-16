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

/** Sincroniza las políticas YAML versionadas del repositorio como borradores (o activas con --activate en desarrollo). */
class PoliciesSync extends Command
{
    protected $signature = 'vulnix:policies:sync {--activate : Activar directamente (solo entornos locales de desarrollo)}';

    protected $description = 'Carga las políticas YAML de /policies en la base de datos';

    public function handle(PolicyLoader $loader): int
    {
        $dir = config('vulnix.policies_dir');
        $files = glob($dir.'/*.yaml') ?: [];
        if (! $files) {
            $this->warn("No hay políticas en {$dir}");

            return self::SUCCESS;
        }
        if ($this->option('activate') && app()->isProduction()) {
            $this->error('--activate no está permitido en producción: las políticas requieren aprobación de un aprobador.');

            return self::FAILURE;
        }
        foreach ($files as $file) {
            $parsed = $loader->fromYaml((string) file_get_contents($file));
            $existing = Policy::where('code', $parsed['code'])->where('version', $parsed['version'])->first();
            if ($existing) {
                $state = $existing->sha256 === $parsed['sha256'] ? 'sin cambios' : 'CONTENIDO DISTINTO: cree una versión nueva';
                $this->line("{$parsed['code']} v{$parsed['version']}: ya existe ({$state}).");

                continue;
            }
            DB::transaction(function () use ($parsed) {
                $policy = Policy::create([
                    'code' => $parsed['code'], 'version' => $parsed['version'], 'rules_json' => $parsed['rules'],
                    'sha256' => $parsed['sha256'], 'source_yaml' => $parsed['source'], 'status' => 'DRAFT',
                ]);
                if ($this->option('activate')) {
                    Policy::where('code', $policy->code)->where('status', 'ACTIVE')->update(['status' => 'RETIRED']);
                    $policy->forceFill(['status' => 'ACTIVE', 'approved_at' => now()])->save();
                }
                Audit::log('policy.synced', 'policy', $policy->id, ['code' => $policy->code, 'version' => $policy->version,
                    'sha256' => $policy->sha256, 'activated' => (bool) $this->option('activate')], null, 'SYSTEM');
            });
            $this->info("{$parsed['code']} v{$parsed['version']} cargada".($this->option('activate') ? ' y ACTIVADA' : ' como DRAFT'));
        }

        return self::SUCCESS;
    }
}
