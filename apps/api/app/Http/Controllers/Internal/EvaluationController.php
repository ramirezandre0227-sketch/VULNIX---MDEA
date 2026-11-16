<?php

namespace App\Http\Controllers\Internal;

use App\Enums\AnalysisStatus;
use App\Exceptions\VulnixException;
use App\Http\Controllers\Controller;
use App\Models\Analysis;
use App\Services\DecisionService;
use Illuminate\Http\JsonResponse;

/**
 * Llamada del orquestador cuando un análisis llega a EVALUATING. El orquestador solo puede
 * solicitar la evaluación: la política la aplica y la firma la emite exclusivamente la API.
 */
class EvaluationController extends Controller
{
    public function evaluate(string $analysisId, DecisionService $decisions): JsonResponse
    {
        $analysis = Analysis::findOrFail($analysisId);
        if ($analysis->status !== AnalysisStatus::Evaluating) {
            throw VulnixException::conflict('ANALYSIS_NOT_EVALUATING', 'El análisis no está pendiente de evaluación.', ['status' => $analysis->status->value]);
        }
        $decision = $decisions->decide($analysis, null, 'SERVICE');

        return response()->json(['decision_id' => $decision->id, 'result' => $decision->result->value], 201);
    }
}
