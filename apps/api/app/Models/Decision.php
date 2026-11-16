<?php

namespace App\Models;

use App\Enums\DecisionResult;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/** Decisión firmada: inmutable (trigger). Cada reevaluación crea una decisión nueva. */
class Decision extends Model
{
    use HasUuids;

    const UPDATED_AT = null;

    protected $table = 'evaluation.decisions';

    protected $fillable = [
        'id', 'analysis_id', 'policy_id', 'result', 'reason_json', 'artifact_sha256', 'policy_sha256',
        'signed_token_uri', 'token_sha256', 'key_id', 'issued_at', 'expires_at', 'issued_by', 'issued_via',
    ];

    protected function casts(): array
    {
        return [
            'result' => DecisionResult::class,
            'reason_json' => 'array',
            'issued_at' => 'datetime',
            'expires_at' => 'datetime',
        ];
    }

    public function analysis(): BelongsTo
    {
        return $this->belongsTo(Analysis::class, 'analysis_id');
    }

    public function policy(): BelongsTo
    {
        return $this->belongsTo(Policy::class, 'policy_id');
    }

    public function toApiArray(): array
    {
        return [
            'id' => $this->id,
            'analysis_id' => $this->analysis_id,
            'result' => $this->result->value,
            'reasons' => $this->reason_json['reasons'] ?? [],
            'summary' => $this->reason_json['summary'] ?? null,
            'artifact_sha256' => $this->artifact_sha256,
            'policy' => ['id' => $this->policy_id, 'sha256' => $this->policy_sha256],
            'key_id' => $this->key_id,
            'token_sha256' => $this->token_sha256,
            'issued_at' => $this->issued_at->toIso8601String(),
            'expires_at' => $this->expires_at->toIso8601String(),
            'issued_via' => $this->issued_via,
            'deployable' => $this->result === DecisionResult::Approved && $this->expires_at->isFuture(),
        ];
    }
}
