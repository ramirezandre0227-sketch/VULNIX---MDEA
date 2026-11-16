<?php

namespace App\Services\Ingest;

use App\Exceptions\VulnixException;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\User;
use App\Support\Audit;
use App\Support\DataStore;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\DB;

/**
 * Ingesta (manual §4): artefacto inmutable, inventario, hashes y validación segura.
 * El artefacto original se guarda tal cual, direccionado por SHA-256; nunca se modifica.
 */
final class ArtifactIngestor
{
    public function __construct(
        private readonly DataStore $store,
        private readonly TechnologyDetector $detector,
    ) {}

    public function ingest(Project $project, User $actor, UploadedFile $upload, string $version): ProjectVersion
    {
        $limits = config('vulnix.ingest');
        $tmpPath = $upload->getRealPath();
        if ($tmpPath === false || ! is_file($tmpPath)) {
            throw new VulnixException('UPLOAD_INVALID', 'La carga no es válida.');
        }
        $size = filesize($tmpPath);
        if ($size === 0 || $size > $limits['max_upload_bytes']) {
            throw new VulnixException('UPLOAD_SIZE_INVALID', 'El archivo está vacío o excede el tamaño permitido.');
        }
        if (ProjectVersion::where('project_id', $project->id)->where('version', $version)->exists()) {
            throw VulnixException::conflict('VERSION_EXISTS', 'Ya existe esa versión para el proyecto (las versiones son inmutables).');
        }

        $sha256 = hash_file('sha256', $tmpPath);
        $originalName = $this->sanitizeName($upload->getClientOriginalName());
        $isZip = $this->looksLikeZip($tmpPath);

        if ($isZip) {
            $inspector = new ZipInspector($limits);
            $inventory = $inspector->inspect($tmpPath);
            $reader = fn (string $p) => $inspector->readSmall($tmpPath, $p);
            $kind = 'ZIP';
            $ext = 'zip';
        } else {
            $ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
            if (! in_array($ext, $limits['single_file_extensions'], true)) {
                throw new VulnixException('UPLOAD_TYPE_NOT_ALLOWED', 'Tipo de archivo no admitido. Use un ZIP o un fuente web.',
                    422, ['allowed' => $limits['single_file_extensions']]);
            }
            $contents = (string) file_get_contents($tmpPath);
            if (str_contains($contents, "\0")) {
                throw new VulnixException('UPLOAD_TYPE_NOT_ALLOWED', 'El archivo parece binario; se esperaba código fuente.');
            }
            $inventory = ['files' => [['path' => $originalName, 'size' => $size, 'sha256' => $sha256]], 'total_bytes' => $size, 'nested_archives' => []];
            $reader = fn (string $p) => $p === $originalName ? $contents : null;
            $kind = 'FILE';
        }

        $technologies = $this->detector->detect($inventory['files'], $reader);
        $uri = sprintf('artifacts/%s/%s/%s.%s', substr($sha256, 0, 2), substr($sha256, 2, 2), $sha256, $ext);
        $this->store->importImmutable($tmpPath, $uri, $sha256);

        return DB::transaction(function () use ($project, $actor, $version, $sha256, $uri, $kind, $originalName, $size, $inventory, $technologies) {
            $pv = ProjectVersion::create([
                'project_id' => $project->id,
                'version' => $version,
                'sha256' => $sha256,
                'uri' => $uri,
                'artifact_kind' => $kind,
                'original_filename' => $originalName,
                'size_bytes' => $size,
                'file_count' => count($inventory['files']),
                'manifest_json' => [
                    'schema' => 'vulnix.manifest/v1',
                    'artifact_sha256' => $sha256,
                    'total_uncompressed_bytes' => $inventory['total_bytes'],
                    'nested_archives' => $inventory['nested_archives'],
                    'files' => $inventory['files'],
                ],
                'technologies' => $technologies,
                'created_by' => $actor->id,
            ]);
            Audit::log('version.registered', 'project_version', $pv->id, [
                'project_id' => $project->id, 'version' => $version, 'sha256' => $sha256,
                'kind' => $kind, 'size_bytes' => $size, 'files' => count($inventory['files']),
            ], $actor);

            return $pv;
        });
    }

    private function looksLikeZip(string $path): bool
    {
        $fh = fopen($path, 'rb');
        $magic = $fh ? fread($fh, 4) : '';
        if ($fh) {
            fclose($fh);
        }

        return $magic === "PK\x03\x04" || $magic === "PK\x05\x06";
    }

    private function sanitizeName(string $name): string
    {
        $name = basename(str_replace('\\', '/', $name));
        $name = preg_replace('/[^A-Za-z0-9._-]/', '_', $name) ?: 'artifact';

        return mb_substr($name, 0, 200);
    }
}
