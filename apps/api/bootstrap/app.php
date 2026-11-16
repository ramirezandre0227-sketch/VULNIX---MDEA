<?php

use App\Exceptions\VulnixException;
use App\Http\Middleware\InternalServiceAuth;
use App\Http\Middleware\RequireAbility;
use App\Http\Middleware\SecurityHeaders;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Illuminate\Session\TokenMismatchException;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
        then: function () {
            Route::middleware(['throttle:internal', InternalServiceAuth::class])
                ->prefix('internal/v1')
                ->group(base_path('routes/internal.php'));
        },
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->statefulApi();
        $middleware->append(SecurityHeaders::class);
        $middleware->alias(['ability' => RequireAbility::class]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $isApi = fn (Request $r) => $r->is('api/*') || $r->is('internal/*');
        $exceptions->shouldRenderJsonWhen(fn (Request $r) => $isApi($r) || $r->expectsJson());
        $exceptions->dontReport([VulnixException::class]);

        $json = fn (string $code, string $message, int $status, array $details = []) => response()->json(
            ['error' => array_filter(['code' => $code, 'message' => $message, 'details' => $details ?: null], fn ($v) => $v !== null)],
            $status,
        );

        // Errores con códigos estables (manual §6).
        $exceptions->render(function (Throwable $e, Request $request) use ($isApi, $json) {
            if (! $isApi($request) && ! $request->expectsJson()) {
                return null;
            }

            return match (true) {
                $e instanceof VulnixException => $json($e->errorCode, $e->getMessage(), $e->status, $e->details),
                $e instanceof ValidationException => $json('VALIDATION_FAILED', 'Datos de entrada inválidos.', 422, $e->errors()),
                $e instanceof AuthenticationException => $json('UNAUTHENTICATED', 'Autenticación requerida.', 401),
                $e instanceof AuthorizationException => $json('FORBIDDEN', 'No tiene permisos para esta operación.', 403),
                $e instanceof ModelNotFoundException,
                $e instanceof NotFoundHttpException => $json('NOT_FOUND', 'Recurso no encontrado.', 404),
                $e instanceof ThrottleRequestsException => $json('RATE_LIMITED', 'Demasiadas solicitudes; intente más tarde.', 429),
                $e instanceof TokenMismatchException => $json('CSRF_TOKEN_MISMATCH', 'Token CSRF inválido o caducado.', 419),
                $e instanceof HttpExceptionInterface => $json('HTTP_'.$e->getStatusCode(), 'Solicitud no válida.', $e->getStatusCode()),
                $e instanceof Illuminate\Database\QueryException && str_contains($e->getMessage(), 'VULNIX_IMMUTABLE')
                    => $json('IMMUTABLE_RECORD', 'El registro es inmutable.', 409),
                $e instanceof Illuminate\Database\QueryException && str_contains($e->getMessage(), 'VULNIX_INVALID_TRANSITION')
                    => $json('INVALID_STATE_TRANSITION', 'Transición de estado no permitida.', 409),
                default => $json('INTERNAL_ERROR', 'Error interno. Consulte los registros con el identificador de la solicitud.', 500),
            };
        });
    })->create();
