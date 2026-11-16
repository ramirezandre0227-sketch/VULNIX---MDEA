<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

class Analyzer extends Model
{
    use HasUuids;

    const UPDATED_AT = null;

    protected $table = 'catalog.analyzers';

    protected $fillable = ['name', 'version', 'category', 'config_hash', 'metadata', 'healthy', 'last_seen_at'];

    protected function casts(): array
    {
        return ['metadata' => 'array', 'healthy' => 'boolean', 'last_seen_at' => 'datetime'];
    }
}
