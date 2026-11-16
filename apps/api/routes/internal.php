<?php

use App\Http\Controllers\Internal\EvaluationController;
use Illuminate\Support\Facades\Route;

// API interna orquestador -> API. Protegida por token de servicio + IP (InternalServiceAuth).
Route::post('/analyses/{analysisId}/evaluate', [EvaluationController::class, 'evaluate'])->whereUuid('analysisId');
