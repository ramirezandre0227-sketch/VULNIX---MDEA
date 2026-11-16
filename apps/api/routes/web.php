<?php

use App\Http\Controllers\WebAppController;
use Illuminate\Support\Facades\Route;

// Frontend estático (apps/web) en el mismo origen que la API.
Route::get('/', [WebAppController::class, 'index']);
Route::get('/assets/{path}', [WebAppController::class, 'asset'])->where('path', '[A-Za-z0-9/_.-]+');
