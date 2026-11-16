<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

class Recommendation extends Model
{
    use HasUuids;

    const UPDATED_AT = null;

    protected $table = 'evaluation.recommendations';

    protected function casts(): array
    {
        return ['references' => 'array'];
    }
}
