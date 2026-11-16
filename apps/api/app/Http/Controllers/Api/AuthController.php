<?php

namespace App\Http\Controllers\Api;

use App\Exceptions\VulnixException;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Support\Audit;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * POST /auth/login. Desde el frontend (mismo origen) crea una sesión con CSRF;
     * desde clientes de API/pipelines devuelve un token Bearer con caducidad.
     */
    public function login(Request $request): JsonResponse
    {
        $data = $request->validate([
            'username' => ['required', 'string', 'max:64'],
            'password' => ['required', 'string', 'max:256'],
            'token_name' => ['nullable', 'string', 'max:64', 'regex:/^[A-Za-z0-9 ._-]+$/'],
        ]);
        $username = User::normalizeUsername($data['username']);
        $user = User::where('username', $username)->first();

        if ($user?->isLocked()) {
            Audit::log('auth.login_locked', 'user', $user->id, ['username' => $username], null, 'ANONYMOUS', $request);
            throw new VulnixException('ACCOUNT_LOCKED', 'Cuenta bloqueada temporalmente por intentos fallidos.', 423);
        }

        // Hash ficticio cuando el usuario no existe: tiempo de respuesta homogéneo.
        $hash = $user?->password_hash ?? Hash::make(bin2hex(random_bytes(16)));
        $valid = Hash::check($data['password'], $hash) && $user && $user->active;

        if (! $valid) {
            if ($user) {
                $user->failed_logins += 1;
                if ($user->failed_logins >= config('vulnix.auth.max_failed_logins')) {
                    $user->locked_until = now()->addMinutes(config('vulnix.auth.lockout_minutes'));
                    $user->failed_logins = 0;
                }
                $user->save();
            }
            Audit::log('auth.login_failed', 'user', $user?->id, ['username' => $username], null, 'ANONYMOUS', $request);
            throw new VulnixException('INVALID_CREDENTIALS', 'Usuario o contraseña incorrectos.', 401);
        }

        $user->forceFill(['failed_logins' => 0, 'locked_until' => null, 'last_login_at' => now()])->save();

        if ($request->hasSession()) {
            Auth::guard('web')->login($user);
            $request->session()->regenerate();
            Audit::log('auth.login', 'user', $user->id, ['mode' => 'session'], $user, 'USER', $request);

            return response()->json(['mode' => 'session', 'user' => $user->toPublicArray()]);
        }

        $expires = now()->addMinutes(config('vulnix.auth.token_ttl_minutes'));
        $token = $user->createToken($data['token_name'] ?? 'api', ['*'], $expires);
        Audit::log('auth.token_issued', 'user', $user->id, ['token_name' => $data['token_name'] ?? 'api', 'expires_at' => $expires->toIso8601String()], $user, 'USER', $request);

        return response()->json([
            'mode' => 'token',
            'token' => $token->plainTextToken,
            'token_type' => 'Bearer',
            'expires_at' => $expires->toIso8601String(),
            'user' => $user->toPublicArray(),
        ]);
    }

    public function me(Request $request): JsonResponse
    {
        return response()->json(['user' => $request->user()->toPublicArray()]);
    }

    public function logout(Request $request): JsonResponse
    {
        $user = $request->user();
        $token = $user->currentAccessToken();
        if ($token && method_exists($token, 'delete') && ! $request->hasSession()) {
            $token->delete();
        } else {
            Auth::guard('web')->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();
        }
        Audit::log('auth.logout', 'user', $user->id, [], $user, 'USER', $request);

        return response()->json(['ok' => true]);
    }
}
