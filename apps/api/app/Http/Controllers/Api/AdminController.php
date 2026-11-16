<?php

namespace App\Http\Controllers\Api;

use App\Enums\Role;
use App\Exceptions\VulnixException;
use App\Http\Controllers\Controller;
use App\Models\AuditLog;
use App\Models\User;
use App\Support\Audit;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Enum;
use Illuminate\Validation\Rules\Password;

/** Auditoría filtrada y gestión de usuarios. */
class AdminController extends Controller
{
    /** GET /audit-logs */
    public function auditLogs(Request $request): JsonResponse
    {
        $f = $request->validate([
            'action' => ['nullable', 'string', 'max:64'],
            'entity_id' => ['nullable', 'string', 'max:64'],
            'actor' => ['nullable', 'string', 'max:64'],
            'from' => ['nullable', 'date'],
            'to' => ['nullable', 'date'],
            'per_page' => ['nullable', 'integer', 'min:1', 'max:200'],
        ]);
        $query = AuditLog::query()->orderByDesc('seq');
        if (! empty($f['action'])) {
            $query->where('action', 'like', addcslashes($f['action'], '%_\\').'%');
        }
        if (! empty($f['entity_id'])) {
            $query->where('entity_id', $f['entity_id']);
        }
        if (! empty($f['actor'])) {
            $query->whereIn('actor_id', User::where('username', $f['actor'])->pluck('id'));
        }
        if (! empty($f['from'])) {
            $query->where('created_at', '>=', $f['from']);
        }
        if (! empty($f['to'])) {
            $query->where('created_at', '<=', $f['to']);
        }
        $page = $query->paginate($f['per_page'] ?? 50);
        $actors = User::whereIn('id', collect($page->items())->pluck('actor_id')->filter()->unique())->pluck('username', 'id');

        return response()->json([
            'data' => collect($page->items())->map(fn (AuditLog $l) => [
                'id' => $l->id, 'seq' => (int) $l->seq, 'actor' => $actors[$l->actor_id] ?? null, 'actor_type' => $l->actor_type,
                'action' => $l->action, 'entity_type' => $l->entity_type, 'entity_id' => $l->entity_id,
                'event' => $l->event_json, 'ip' => $l->ip, 'hash' => $l->hash, 'prev_hash' => $l->prev_hash,
                'created_at' => $l->created_at?->toIso8601String(),
            ]),
            'meta' => ['page' => $page->currentPage(), 'per_page' => $page->perPage(), 'total' => $page->total()],
        ]);
    }

    /** GET /audit-logs/verify: recomputa la cadena de hashes completa. */
    public function verifyAudit(): JsonResponse
    {
        return response()->json(['data' => self::verifyChain()]);
    }

    public static function verifyChain(): array
    {
        $broken = DB::select(<<<'SQL'
            SELECT seq, id FROM (
              SELECT seq, id, hash, prev_hash,
                     lag(hash) OVER (ORDER BY seq) AS expected_prev,
                     lag(seq) OVER (ORDER BY seq) AS prev_seq,
                     audit.row_hash(prev_hash, seq, actor_id, actor_type, action, entity_type, entity_id, event_json, created_at) AS recomputed
              FROM audit.audit_logs) t
            WHERE hash IS DISTINCT FROM recomputed
               OR prev_hash IS DISTINCT FROM expected_prev
               OR (prev_seq IS NOT NULL AND seq <> prev_seq + 1)
            ORDER BY seq LIMIT 20
        SQL);
        $count = (int) DB::scalar('SELECT count(*) FROM audit.audit_logs');

        return ['valid' => $broken === [], 'entries' => $count, 'broken' => array_map(fn ($r) => ['seq' => (int) $r->seq, 'id' => $r->id], $broken)];
    }

    public function users(): JsonResponse
    {
        return response()->json(['data' => User::orderBy('username')->get()->map->toPublicArray()->values()]);
    }

    public function storeUser(Request $request): JsonResponse
    {
        $data = $request->validate([
            'username' => ['required', 'string', 'max:64'],
            'display_name' => ['required', 'string', 'max:120'],
            'email' => ['nullable', 'email', 'max:190', 'unique:identity.users,email'],
            'role' => ['required', new Enum(Role::class)],
            'password' => ['required', 'string', Password::min(12)->letters()->mixedCase()->numbers()],
        ]);
        $data['username'] = User::normalizeUsername($data['username']);
        if (! User::validUsername($data['username'])) {
            throw new VulnixException('VALIDATION_FAILED', 'Usuario inválido: 3-64 caracteres a-z, 0-9, punto, guion, guion bajo o espacios internos.', 422);
        }
        if (User::where('username', $data['username'])->exists()) {
            throw VulnixException::conflict('USERNAME_TAKEN', 'Ese nombre de usuario ya existe.');
        }
        $this->guardSuperadmin($request, $data['role']);
        $user = User::create([
            'username' => $data['username'], 'display_name' => $data['display_name'], 'email' => $data['email'] ?? null,
            'role' => $data['role'], 'password_hash' => $data['password'], 'active' => true,
        ]);
        Audit::log('user.created', 'user', $user->id, ['username' => $user->username, 'role' => $user->role->value]);

        return response()->json(['data' => $user->toPublicArray()], 201);
    }

    public function updateUser(Request $request, User $user): JsonResponse
    {
        $data = $request->validate([
            'role' => ['nullable', new Enum(Role::class)],
            'active' => ['nullable', 'boolean'],
            'display_name' => ['nullable', 'string', 'max:120'],
            'password' => ['nullable', 'string', Password::min(12)->letters()->mixedCase()->numbers()],
        ]);
        if ($user->id === $request->user()->id && (isset($data['role']) || (($data['active'] ?? true) === false))) {
            throw VulnixException::forbidden('No puede cambiar su propio rol ni desactivarse.');
        }
        // Un administrador no puede tocar a un superadmin ni ascender a nadie a superadmin (escalada de privilegios).
        $this->guardSuperadmin($request, $user->role->value);
        $this->guardSuperadmin($request, $data['role'] ?? null);
        $changes = array_filter(['role' => $data['role'] ?? null, 'active' => $data['active'] ?? null, 'display_name' => $data['display_name'] ?? null],
            fn ($v) => $v !== null);
        if (! empty($data['password'])) {
            $changes['password_hash'] = $data['password'];
            $changes['failed_logins'] = 0;
            $changes['locked_until'] = null;
        }
        $user->forceFill($changes)->save();
        if (($data['active'] ?? true) === false || isset($data['role']) || ! empty($data['password'])) {
            $user->tokens()->delete(); // revoca tokens activos ante cambios de privilegio
        }
        Audit::log('user.updated', 'user', $user->id, ['fields' => array_keys($changes)]);

        return response()->json(['data' => $user->fresh()->toPublicArray()]);
    }

    private function guardSuperadmin(Request $request, ?string $role): void
    {
        if ($role === Role::Superadmin->value && ! $request->user()->canDo('users.manage_superadmin')) {
            throw VulnixException::forbidden('Solo un superadministrador puede gestionar cuentas de superadministrador.');
        }
    }
}
