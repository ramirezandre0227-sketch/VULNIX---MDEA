<?php

namespace App\Models;

use App\Enums\Role;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasUuids;

    protected $table = 'identity.users';

    protected $authPasswordName = 'password_hash';

    protected $fillable = ['username', 'display_name', 'email', 'password_hash', 'role', 'active'];

    protected $hidden = ['password_hash', 'remember_token', 'failed_logins', 'locked_until'];

    protected function casts(): array
    {
        return [
            'role' => Role::class,
            'active' => 'boolean',
            'locked_until' => 'datetime',
            'last_login_at' => 'datetime',
            'password_hash' => 'hashed',
        ];
    }

    /** Minúsculas, sin espacios en los extremos y con espacios internos simples: el login no distingue mayúsculas. */
    public static function normalizeUsername(string $username): string
    {
        return strtolower(trim((string) preg_replace('/\s+/u', ' ', $username)));
    }

    public static function validUsername(string $username): bool
    {
        return (bool) preg_match('/^[a-z0-9._-][a-z0-9._ -]{1,62}[a-z0-9._-]$/', $username) && ! str_contains($username, '  ');
    }

    public function canDo(string $ability): bool
    {
        return $this->active && $this->role->can($ability);
    }

    public function isLocked(): bool
    {
        return $this->locked_until !== null && $this->locked_until->isFuture();
    }

    public function toPublicArray(): array
    {
        return [
            'id' => $this->id,
            'username' => $this->username,
            'display_name' => $this->display_name,
            'email' => $this->email,
            'role' => $this->role->value,
            'role_label' => $this->role->label(),
            'active' => $this->active,
            'abilities' => $this->role->abilities(),
            'last_login_at' => $this->last_login_at?->toIso8601String(),
        ];
    }
}
