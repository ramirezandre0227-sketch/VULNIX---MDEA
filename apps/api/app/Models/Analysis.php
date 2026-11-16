<?php

namespace App\Models;

use App\Enums\AnalysisStatus;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Support\Collection;
use LogicException;

class Analysis extends Model
{
    use HasUuids;

    protected $table = 'evaluation.analyses';

    protected $fillable = [
        'version_id', 'policy_id', 'profile', 'status', 'status_reason', 'artifact_sha256',
        'dynamic_testing', 'requested_by', 'client_request_key',
    ];

    protected function casts(): array
    {
        return [
            'status' => AnalysisStatus::class,
            'dynamic_testing' => 'array',
            'started_at' => 'datetime',
            'finished_at' => 'datetime',
        ];
    }

    public function version(): BelongsTo
    {
        return $this->belongsTo(ProjectVersion::class, 'version_id');
    }

    public function policy(): BelongsTo
    {
        return $this->belongsTo(Policy::class, 'policy_id');
    }

    public function requester(): BelongsTo
    {
        return $this->belongsTo(User::class, 'requested_by');
    }

    public function jobs(): HasMany
    {
        return $this->hasMany(ScanJob::class, 'analysis_id')
            ->orderBy('category')->orderBy('analyzer_name')->orderBy('attempt');
    }

    public function findings(): HasMany
    {
        return $this->hasMany(Finding::class, 'analysis_id');
    }

    public function decisions(): HasMany
    {
        return $this->hasMany(Decision::class, 'analysis_id')->orderByDesc('created_at');
    }

    public function latestDecision(): HasOne
    {
        // latestOfMany() desempata con max(id), que PostgreSQL no admite para uuid: se usa orden explícito.
        return $this->hasOne(Decision::class, 'analysis_id')->orderByDesc('created_at')->orderByDesc('issued_at');
    }

    /** Transición validada en la aplicación (la BD vuelve a validarla por trigger). */
    public function transitionTo(AnalysisStatus $next, ?string $reason = null): void
    {
        if (! $this->status->canTransitionTo($next)) {
            throw new LogicException("Transición inválida {$this->status->value} -> {$next->value}");
        }
        $this->status = $next;
        if ($reason !== null) {
            $this->status_reason = $reason;
        }
        if ($next->isTerminal() && $this->finished_at === null) {
            $this->finished_at = now();
        }
        $this->save();
    }

    /**
     * Último intento por analizador (los reintentos crean filas nuevas; se evalúa el último).
     *
     * @return Collection<int, ScanJob>
     */
    public function latestJobs(): Collection
    {
        return $this->jobs()->with('analyzer')->get()->groupBy('analyzer_name')
            ->map(fn (Collection $attempts) => $attempts->sortByDesc('attempt')->first())
            ->values();
    }

    public function toApiArray(): array
    {
        $version = $this->version;

        return [
            'id' => $this->id,
            'status' => $this->status->value,
            'status_reason' => $this->status_reason,
            'profile' => $this->profile,
            'policy' => $this->policy ? [
                'id' => $this->policy->id, 'code' => $this->policy->code,
                'version' => $this->policy->version, 'sha256' => $this->policy->sha256,
            ] : null,
            'artifact_sha256' => $this->artifact_sha256,
            'project_version' => $version ? [
                'id' => $version->id, 'version' => $version->version,
                'project_id' => $version->project_id, 'project_name' => $version->project?->name,
            ] : null,
            'dynamic_testing' => $this->dynamic_testing,
            'requested_by' => $this->requester?->username,
            'created_at' => $this->created_at?->toIso8601String(),
            'started_at' => $this->started_at?->toIso8601String(),
            'finished_at' => $this->finished_at?->toIso8601String(),
        ];
    }
}
