<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/** Registro append-only: UPDATE/DELETE bloqueados por trigger; la cadena de hashes la calcula la BD. */
class AuditLog extends Model
{
    use HasUuids;

    public $timestamps = false;

    protected $table = 'audit.audit_logs';

    protected $fillable = ['actor_id', 'actor_type', 'action', 'entity_type', 'entity_id', 'event_json', 'ip', 'user_agent'];

    protected function casts(): array
    {
        return ['event_json' => 'array', 'created_at' => 'datetime'];
    }
}
