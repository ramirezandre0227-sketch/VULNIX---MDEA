<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

class Report extends Model
{
    use HasUuids;

    const UPDATED_AT = null;

    protected $table = 'evaluation.reports';

    protected $fillable = ['analysis_id', 'decision_id', 'format', 'uri', 'sha256', 'size_bytes', 'created_by'];
}
