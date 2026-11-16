<?php

namespace App\Support;

use App\Exceptions\VulnixException;
use App\Models\Analysis;
use App\Models\Project;
use App\Models\User;
use Illuminate\Database\Eloquent\Builder;

/** Autorización a nivel de objeto: un desarrollador solo ve sus proyectos; los demás roles ven todos. */
final class Access
{
    public static function canViewProject(User $user, Project $project): bool
    {
        return $user->canDo('projects.view_all') || $project->owner_id === $user->id;
    }

    public static function ensureProject(User $user, Project $project): void
    {
        if (! self::canViewProject($user, $project)) {
            // 404 para no revelar la existencia de proyectos ajenos.
            throw new VulnixException('NOT_FOUND', 'Recurso no encontrado.', 404);
        }
    }

    public static function ensureAnalysis(User $user, Analysis $analysis): void
    {
        self::ensureProject($user, $analysis->version->project);
    }

    public static function scopeProjects(Builder $query, User $user): Builder
    {
        return $user->canDo('projects.view_all') ? $query : $query->where('owner_id', $user->id);
    }
}
