<?php

namespace App\Models;

use App\Enums\ExceptionStatus;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/** Excepción sobre un hallazgo: resolución auditable separada, con aprobador y vencimiento. */
class FindingException extends Model
{
    use HasUuids;

    protected $table = 'evaluation.exceptions';

    protected $fillable = ['finding_id', 'requested_by', 'kind', 'reason', 'expires_at', 'status'];

    protected function casts(): array
    {
        return [
            'status' => ExceptionStatus::class,
            'expires_at' => 'datetime',
            'decided_at' => 'datetime',
        ];
    }

    public function finding(): BelongsTo
    {
        return $this->belongsTo(Finding::class, 'finding_id');
    }

    public function requester(): BelongsTo
    {
        return $this->belongsTo(User::class, 'requested_by');
    }

    public function approver(): BelongsTo
    {
        return $this->belongsTo(User::class, 'approver_id');
    }

    public function isEffective(): bool
    {
        return $this->status === ExceptionStatus::Approved && $this->expires_at->isFuture();
    }

    public function toApiArray(): array
    {
        return [
            'id' => $this->id,
            'finding_id' => $this->finding_id,
            'kind' => $this->kind,
            'reason' => $this->reason,
            'status' => $this->status->value,
            'effective' => $this->isEffective(),
            'expires_at' => $this->expires_at->toIso8601String(),
            'requested_by' => $this->requester?->username,
            'approver' => $this->approver?->username,
            'decision_note' => $this->decision_note,
            'decided_at' => $this->decided_at?->toIso8601String(),
            'created_at' => $this->created_at?->toIso8601String(),
        ];
    }
}
