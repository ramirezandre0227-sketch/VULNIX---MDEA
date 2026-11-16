<?php

namespace App\Enums;

/**
 * Roles separados (manual §11). Las capacidades se asignan con mínimo privilegio y
 * segregación de funciones: quien solicita una excepción o crea una política no la aprueba.
 */
enum Role: string
{
    case Developer = 'developer';
    case SecurityReviewer = 'security_reviewer';
    case Approver = 'approver';
    case Admin = 'admin';
    case Auditor = 'auditor';
    case Superadmin = 'superadmin';

    /**
     * Superadmin = unión de las capacidades de todos los roles. La segregación de funciones sobre
     * elementos propios (no aprobar sus propias excepciones/políticas) se mantiene: la exige el manual
     * y la impone la base de datos (CHECK exceptions_sod_chk / policies_sod_chk).
     *
     * @return list<string>
     */
    public function abilities(): array
    {
        if ($this === self::Superadmin) {
            $all = [];
            foreach (self::cases() as $role) {
                if ($role !== self::Superadmin) {
                    $all = array_merge($all, $role->abilities());
                }
            }

            return array_values(array_unique([...$all, 'users.manage_superadmin']));
        }

        return match ($this) {
            self::Developer => [
                'projects.create', 'versions.upload', 'analyses.create', 'analyses.evaluate',
                'exceptions.request', 'reports.download',
            ],
            self::SecurityReviewer => [
                'projects.view_all', 'projects.create', 'versions.upload', 'analyses.create', 'analyses.evaluate',
                'exceptions.request', 'policies.create', 'reports.download',
            ],
            self::Approver => [
                'projects.view_all', 'exceptions.decide', 'policies.approve', 'reports.download',
            ],
            self::Admin => [
                'projects.view_all', 'projects.create', 'versions.upload', 'analyses.create', 'analyses.evaluate',
                'policies.create', 'users.manage', 'audit.view', 'reports.download', 'system.view',
            ],
            self::Auditor => [
                'projects.view_all', 'audit.view', 'reports.download', 'system.view',
            ],
        };
    }

    public function can(string $ability): bool
    {
        return in_array($ability, $this->abilities(), true);
    }

    public function label(): string
    {
        return match ($this) {
            self::Developer => 'Desarrollador',
            self::SecurityReviewer => 'Revisor de seguridad',
            self::Approver => 'Aprobador',
            self::Admin => 'Administrador',
            self::Auditor => 'Auditor',
            self::Superadmin => 'Superadministrador',
        };
    }
}
