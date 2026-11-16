<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

/** Artefacto inmutable identificado por SHA-256 (un trigger impide modificar su identidad). */
class ProjectVersion extends Model
{
    use HasUuids;

    const UPDATED_AT = null;

    protected $table = 'catalog.project_versions';

    protected $fillable = [
        'project_id', 'version', 'sha256', 'uri', 'artifact_kind', 'original_filename',
        'size_bytes', 'file_count', 'manifest_json', 'technologies', 'created_by',
    ];

    protected $hidden = ['manifest_json'];

    protected function casts(): array
    {
        return ['manifest_json' => 'array', 'technologies' => 'array', 'size_bytes' => 'integer'];
    }

    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class, 'project_id');
    }

    public function analyses(): HasMany
    {
        return $this->hasMany(Analysis::class, 'version_id')->orderByDesc('created_at');
    }
}
