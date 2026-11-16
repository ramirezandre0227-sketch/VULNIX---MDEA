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

/** Gate de despliegue: verifica firma, vigencia, resultado APPROVED e identidad (SHA-256) del artefacto. */
class VerifyAuthorization extends Command
{
    protected $signature = 'vulnix:verify-authorization {token : Fichero .jws} {artifact : Artefacto a desplegar}';

    protected $description = 'Verifica una autorización de despliegue contra el artefacto exacto';

    public function handle(DecisionSigner $signer): int
    {
        $token = @file_get_contents((string) $this->argument('token'));
        $artifact = (string) $this->argument('artifact');
        if ($token === false || ! is_file($artifact)) {
            $this->error('No se pudo leer el token o el artefacto.');

            return self::FAILURE;
        }
        $sha = hash_file('sha256', $artifact);
        $r = $signer->verify($token, $sha);
        if ($r['valid']) {
            $this->info("AUTORIZADO: análisis {$r['claims']['analysis_id']}, artefacto {$sha}, vence {$r['claims']['expires_at']}");

            return self::SUCCESS;
        }
        $this->error('DESPLIEGUE BLOQUEADO: '.implode(', ', $r['errors']));

        return self::FAILURE;
    }
}
