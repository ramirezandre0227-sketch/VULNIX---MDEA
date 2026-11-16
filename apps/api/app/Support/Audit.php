<?php

namespace App\Support;

use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Http\Request;

/**
 * Registro de auditoría. La cadena de hashes la calcula un trigger en PostgreSQL;
 * aquí solo se garantiza que el evento no contenga secretos (claves sensibles se eliminan).
 */
final class Audit
{
    private const SENSITIVE_KEYS = ['password', 'password_hash', 'token', 'secret', 'authorization', 'cookie'];

    public static function log(string $action, ?string $entityType = null, ?string $entityId = null, array $event = [],
        ?User $actor = null, string $actorType = 'USER', ?Request $request = null): void
    {
        $request ??= request();
        $actor ??= $request?->user();

        AuditLog::create([
            'actor_id' => $actor?->id,
            'actor_type' => $actor ? $actorType : ($actorType === 'USER' ? 'ANONYMOUS' : $actorType),
            'action' => $action,
            'entity_type' => $entityType,
            'entity_id' => $entityId,
            'event_json' => self::scrub($event),
            'ip' => $request?->ip(),
            'user_agent' => $request ? mb_substr((string) $request->userAgent(), 0, 255) : null,
        ]);
    }

    private static function scrub(array $data): array
    {
        foreach ($data as $key => $value) {
            if (is_string($key) && in_array(strtolower($key), self::SENSITIVE_KEYS, true)) {
                $data[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $data[$key] = self::scrub($value);
            }
        }

        return $data;
    }
}
