<?php

namespace App\Services;

use App\Models\Analysis;
use App\Models\Finding;

/** Comparación entre análisis por huella estable: nuevos, corregidos y persistentes. */
final class VersionComparator
{
    public function compare(Analysis $base, Analysis $target): array
    {
        $baseFindings = Finding::where('analysis_id', $base->id)->get()->keyBy('fingerprint');
        $targetFindings = Finding::where('analysis_id', $target->id)->get()->keyBy('fingerprint');

        $new = $targetFindings->diffKeys($baseFindings)->values();
        $fixed = $baseFindings->diffKeys($targetFindings)->values();
        $persisting = $targetFindings->intersectByKeys($baseFindings)->values();
        $fmt = fn ($c) => $c->map->toApiArray()->values()->all();

        return [
            'base' => ['analysis_id' => $base->id, 'version' => $base->version->version, 'artifact_sha256' => $base->artifact_sha256],
            'target' => ['analysis_id' => $target->id, 'version' => $target->version->version, 'artifact_sha256' => $target->artifact_sha256],
            'counts' => ['new' => $new->count(), 'fixed' => $fixed->count(), 'persisting' => $persisting->count()],
            'new' => $fmt($new),
            'fixed' => $fmt($fixed),
            'persisting' => $fmt($persisting),
        ];
    }
}
