<?php

namespace App\Http\Middleware;

use App\Exceptions\VulnixException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Autenticación entre servicios (manual §6) para /internal/*: token compartido comparado en tiempo
 * constante + lista de IPs permitidas. Estas rutas no son accesibles para usuarios.
 */
class InternalServiceAuth
{
    public function handle(Request $request, Closure $next): Response
    {
        $expected = (string) config('vulnix.internal_token');
        $given = (string) $request->header('X-Vulnix-Service-Token', '');
        if (strlen($expected) < 32 || ! hash_equals($expected, $given)) {
            throw new VulnixException('SERVICE_UNAUTHENTICATED', 'Credencial de servicio inválida.', 401);
        }
        if (! in_array($request->ip(), config('vulnix.internal_allowed_ips'), true)) {
            throw new VulnixException('SERVICE_FORBIDDEN', 'Origen no autorizado para la API interna.', 403);
        }

        return $next($request);
    }
}
