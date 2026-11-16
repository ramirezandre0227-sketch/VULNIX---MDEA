<?php

namespace App\Models;

use App\Enums\Severity;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

/** Resultado bruto normalizado: inmutable. Las excepciones son resoluciones separadas. */
class Finding extends Model
{
    use HasUuids;

    const UPDATED_AT = null;

    protected $table = 'evaluation.findings';

    protected function casts(): array
    {
        return ['severity' => Severity::class, 'metadata' => 'array'];
    }

    public function analysis(): BelongsTo
    {
        return $this->belongsTo(Analysis::class, 'analysis_id');
    }

    public function job(): BelongsTo
    {
        return $this->belongsTo(ScanJob::class, 'job_id');
    }

    public function evidences(): HasMany
    {
        return $this->hasMany(Evidence::class, 'finding_id');
    }

    public function recommendations(): HasMany
    {
        return $this->hasMany(Recommendation::class, 'finding_id');
    }

    public function exceptions(): HasMany
    {
        return $this->hasMany(FindingException::class, 'finding_id')->orderByDesc('created_at');
    }

    public function toApiArray(): array
    {
        return [
            'id' => $this->id,
            'analysis_id' => $this->analysis_id,
            'fingerprint' => $this->fingerprint,
            'correlation_key' => $this->correlation_key,
            'rule_id' => $this->rule_id,
            'analyzer' => $this->analyzer_name,
            'category' => $this->category,
            'title' => $this->title,
            'severity' => $this->severity->value,
            'confidence' => $this->confidence,
            'cwe' => $this->cwe,
            'location' => ['file' => $this->file_path, 'line' => $this->start_line, 'end_line' => $this->end_line],
            'description' => $this->description,
            'remediation' => $this->remediation,
            'status' => $this->status,
        ];
    }
}
