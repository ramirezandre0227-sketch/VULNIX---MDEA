<?php

use App\Http\Controllers\Api\AdminController;
use App\Http\Controllers\Api\AnalysisController;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\DashboardController;
use App\Http\Controllers\Api\DecisionController;
use App\Http\Controllers\Api\ExceptionController;
use App\Http\Controllers\Api\FindingController;
use App\Http\Controllers\Api\PolicyController;
use App\Http\Controllers\Api\ProjectController;
use Illuminate\Support\Facades\Route;

/*
| API REST /api/v1 (manual §6). Autenticación: sesión (frontend mismo origen + CSRF) o token Bearer.
| RBAC por capacidades (middleware "ability") + autorización por objeto (App\Support\Access).
*/
Route::prefix('v1')->group(function () {
    Route::post('/auth/login', [AuthController::class, 'login'])->middleware('throttle:login');

    Route::middleware(['auth:sanctum', 'throttle:api'])->group(function () {
        Route::get('/auth/me', [AuthController::class, 'me']);
        Route::post('/auth/logout', [AuthController::class, 'logout']);

        Route::get('/dashboard', [DashboardController::class, 'index']);
        Route::get('/system/health', [DashboardController::class, 'health'])->middleware('ability:system.view,projects.view_all');

        Route::get('/projects', [ProjectController::class, 'index']);
        Route::post('/projects', [ProjectController::class, 'store'])->middleware('ability:projects.create');
        Route::get('/projects/{project}', [ProjectController::class, 'show'])->whereUuid('project');
        Route::post('/projects/{project}/versions', [ProjectController::class, 'storeVersion'])
            ->whereUuid('project')->middleware(['ability:versions.upload', 'throttle:uploads']);

        Route::get('/analyses', [AnalysisController::class, 'index']);
        Route::post('/analyses', [AnalysisController::class, 'store'])->middleware('ability:analyses.create');
        Route::get('/analyses/{analysis}', [AnalysisController::class, 'show'])->whereUuid('analysis');
        Route::get('/analyses/{analysis}/findings', [AnalysisController::class, 'findings'])->whereUuid('analysis');
        Route::post('/analyses/{analysis}/evaluate', [AnalysisController::class, 'evaluate'])->whereUuid('analysis')->middleware('ability:analyses.evaluate');
        Route::post('/analyses/{analysis}/cancel', [AnalysisController::class, 'cancel'])->whereUuid('analysis')->middleware('ability:analyses.create');
        Route::get('/analyses/{analysis}/compare/{other}', [AnalysisController::class, 'compare'])->whereUuid(['analysis', 'other']);
        Route::get('/analyses/{analysis}/decision', [DecisionController::class, 'show'])->whereUuid('analysis');
        Route::get('/analyses/{analysis}/decision/token', [DecisionController::class, 'token'])->whereUuid('analysis');
        Route::get('/analyses/{analysis}/report', [DecisionController::class, 'report'])->whereUuid('analysis');

        Route::get('/findings/{finding}', [FindingController::class, 'show'])->whereUuid('finding');
        Route::get('/evidences/{evidence}/download', [FindingController::class, 'downloadEvidence'])->whereUuid('evidence');

        Route::get('/authorization/public-key', [DecisionController::class, 'publicKey']);
        Route::post('/authorization/verify', [DecisionController::class, 'verify']);

        Route::get('/policies', [PolicyController::class, 'index']);
        Route::get('/policies/{policy}', [PolicyController::class, 'show'])->whereUuid('policy');
        Route::post('/policies', [PolicyController::class, 'store'])->middleware('ability:policies.create');
        Route::post('/policies/{policy}/approve', [PolicyController::class, 'approve'])->whereUuid('policy')->middleware('ability:policies.approve');

        Route::get('/exceptions', [ExceptionController::class, 'index']);
        Route::post('/exceptions', [ExceptionController::class, 'store'])->middleware('ability:exceptions.request');
        Route::post('/exceptions/{exception}/decision', [ExceptionController::class, 'decide'])->whereUuid('exception')->middleware('ability:exceptions.decide');

        Route::get('/audit-logs', [AdminController::class, 'auditLogs'])->middleware('ability:audit.view');
        Route::get('/audit-logs/verify', [AdminController::class, 'verifyAudit'])->middleware('ability:audit.view');

        Route::get('/users', [AdminController::class, 'users'])->middleware('ability:users.manage');
        Route::post('/users', [AdminController::class, 'storeUser'])->middleware('ability:users.manage');
        Route::patch('/users/{user}', [AdminController::class, 'updateUser'])->whereUuid('user')->middleware('ability:users.manage');
    });
});
