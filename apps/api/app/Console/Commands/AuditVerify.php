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

/** Verifica la cadena de hashes de la auditoría. */
class AuditVerify extends Command
{
    protected $signature = 'vulnix:audit:verify';

    protected $description = 'Verifica la integridad de la cadena de auditoría';

    public function handle(): int
    {
        $r = AdminController::verifyChain();
        if ($r['valid']) {
            $this->info("Cadena íntegra: {$r['entries']} entradas.");

            return self::SUCCESS;
        }
        $this->error('Cadena ROTA en: '.json_encode($r['broken']));

        return self::FAILURE;
    }
}
