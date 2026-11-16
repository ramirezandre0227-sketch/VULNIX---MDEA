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

/** Genera (o rota) el par de claves Ed25519 de firma de decisiones. */
class KeysGenerate extends Command
{
    protected $signature = 'vulnix:keys:generate {--force : Rotar el par existente (se archiva el anterior)}';

    protected $description = 'Genera el par de claves Ed25519 para firmar autorizaciones de despliegue';

    public function handle(DecisionSigner $signer): int
    {
        if ($signer->hasKeys() && ! $this->option('force')) {
            $this->info("Ya existe un par de claves (kid {$signer->keyId()}). Use --force para rotarlo.");

            return self::SUCCESS;
        }
        $keys = $signer->generateKeys((bool) $this->option('force'));
        Audit::log('signing_key.generated', 'signing_key', $keys['key_id'], ['rotated' => (bool) $this->option('force')], null, 'SYSTEM');
        $this->info("Clave generada. kid={$keys['key_id']}");
        $this->line("Clave pública (base64): {$keys['public_key']}");

        return self::SUCCESS;
    }
}
