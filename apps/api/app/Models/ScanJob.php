<?php

namespace App\Models;

use App\Enums\JobStatus;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class ScanJob extends Model
{
    use HasUuids;

    protected $table = 'evaluation.scan_jobs';

    protected $fillable = [
        'analysis_id', 'analyzer_id', 'analyzer_name', 'category', 'mandatory', 'attempt',
        'max_attempts', 'status', 'idempotency_key', 'error_type', 'error_message', 'metadata',
    ];

    protected function casts(): array
    {
        return [
            'status' => JobStatus::class,
            'mandatory' => 'boolean',
            'metadata' => 'array',
            'started_at' => 'datetime',
            'ended_at' => 'datetime',
            'lease_expires_at' => 'datetime',
        ];
    }

    public function analysis(): BelongsTo
    {
        return $this->belongsTo(Analysis::class, 'analysis_id');
    }

    public function analyzer(): BelongsTo
    {
        return $this->belongsTo(Analyzer::class, 'analyzer_id');
    }

    public function evidences(): HasMany
    {
        return $this->hasMany(Evidence::class, 'job_id');
    }

    public function toApiArray(): array
    {
        return [
            'id' => $this->id,
            'analyzer' => $this->analyzer_name,
            'analyzer_version' => $this->analyzer?->version,
            'category' => $this->category,
            'mandatory' => $this->mandatory,
            'attempt' => $this->attempt,
            'status' => $this->status->value,
            'exit_code' => $this->exit_code,
            'error_type' => $this->error_type,
            'error_message' => $this->error_message,
            'metadata' => $this->metadata,
            'started_at' => $this->started_at?->toIso8601String(),
            'ended_at' => $this->ended_at?->toIso8601String(),
        ];
    }
}
