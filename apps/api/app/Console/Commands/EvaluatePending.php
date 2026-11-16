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

/** Respaldo de la notificación del orquestador: evalúa análisis que quedaron en EVALUATING. */
class EvaluatePending extends Command
{
    protected $signature = 'vulnix:evaluate-pending';

    protected $description = 'Emite decisiones para análisis pendientes de evaluación';

    public function handle(DecisionService $decisions): int
    {
        $pending = Analysis::where('status', AnalysisStatus::Evaluating->value)->get();
        foreach ($pending as $analysis) {
            try {
                $d = $decisions->decide($analysis, null, 'SERVICE');
                $this->info("{$analysis->id}: {$d->result->value}");
            } catch (Throwable $e) {
                $this->error("{$analysis->id}: {$e->getMessage()}");
            }
        }
        $this->line(count($pending).' análisis procesados.');

        return self::SUCCESS;
    }
}
