<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/** Política versionada: su contenido es inmutable (trigger); solo cambia el ciclo de vida. */
class Policy extends Model
{
    use HasUuids;

    const UPDATED_AT = null;

    protected $table = 'catalog.policies';

    protected $fillable = ['code', 'version', 'rules_json', 'sha256', 'source_yaml', 'status', 'created_by'];

    protected function casts(): array
    {
        return ['rules_json' => 'array', 'approved_at' => 'datetime'];
    }

    public function creator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    public function approver(): BelongsTo
    {
        return $this->belongsTo(User::class, 'approved_by');
    }

    public static function activeFor(string $code): ?self
    {
        return static::query()->where('code', $code)->where('status', 'ACTIVE')
            ->orderByDesc('approved_at')->orderByDesc('created_at')->first();
    }

    public function toApiArray(bool $withSource = false): array
    {
        $data = [
            'id' => $this->id,
            'code' => $this->code,
            'version' => $this->version,
            'status' => $this->status,
            'sha256' => $this->sha256,
            'rules' => $this->rules_json,
            'created_by' => $this->creator?->username,
            'approved_by' => $this->approver?->username,
            'approved_at' => $this->approved_at?->toIso8601String(),
            'created_at' => $this->created_at?->toIso8601String(),
        ];
        if ($withSource) {
            $data['source_yaml'] = $this->source_yaml;
        }

        return $data;
    }
}
