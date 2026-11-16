<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/** Evidencia inmutable (trigger) con hash SHA-256 del contenido almacenado. */
class Evidence extends Model
{
    use HasUuids;

    const UPDATED_AT = null;

    protected $table = 'evaluation.evidences';

    public function toApiArray(): array
    {
        return [
            'id' => $this->id,
            'kind' => $this->kind,
            'sha256' => $this->sha256,
            'size_bytes' => (int) $this->size_bytes,
            'created_at' => $this->created_at?->toIso8601String(),
        ];
    }
}
