<?php

namespace App\Http\Middleware;

use App\Exceptions\VulnixException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** RBAC: exige una capacidad del rol del usuario (uso: ->middleware('ability:policies.create')). */
class RequireAbility
{
    public function handle(Request $request, Closure $next, string ...$abilities): Response
    {
        $user = $request->user();
        if (! $user || ! $user->active) {
            throw new VulnixException('UNAUTHENTICATED', 'Autenticación requerida.', 401);
        }
        foreach ($abilities as $ability) {
            if ($user->canDo($ability)) {
                return $next($request);
            }
        }
        throw VulnixException::forbidden();
    }
}
