<?php

namespace App\Support;

use App\Exceptions\VulnixException;

/**
 * Almacén de ficheros compartido (artefactos, evidencias, reportes, decisiones).
 * Las URIs guardadas en BD son relativas al directorio de datos y se validan contra traversal.
 */
final class DataStore
{
    public function root(): string
    {
        return config('vulnix.data_dir');
    }

    public function path(string $relative): string
    {
        $relative = str_replace('\\', '/', $relative);
        if ($relative === '' || str_starts_with($relative, '/') || preg_match('#(^|/)\.\.(/|$)#', $relative)
            || preg_match('/^[A-Za-z]:/', $relative) || str_contains($relative, "\0")) {
            throw new VulnixException('STORAGE_PATH_INVALID', 'Ruta de almacenamiento inválida.', 500);
        }

        return $this->root().'/'.$relative;
    }

    public function exists(string $relative): bool
    {
        return is_file($this->path($relative));
    }

    /** Escribe un fichero nuevo de forma atómica y lo marca de solo lectura. No sobrescribe. */
    public function putImmutable(string $relative, string $contents): array
    {
        $target = $this->path($relative);
        $this->ensureDir(dirname($target));
        $sha = hash('sha256', $contents);
        if (is_file($target)) {
            if (hash_file('sha256', $target) !== $sha) {
                throw new VulnixException('STORAGE_CONFLICT', 'El fichero inmutable ya existe con otro contenido.', 500);
            }

            return ['uri' => $relative, 'sha256' => $sha, 'size' => strlen($contents)];
        }
        $tmp = $target.'.tmp-'.bin2hex(random_bytes(6));
        if (file_put_contents($tmp, $contents, LOCK_EX) === false || ! rename($tmp, $target)) {
            @unlink($tmp);
            throw new VulnixException('STORAGE_WRITE_FAILED', 'No se pudo escribir en el almacenamiento.', 500);
        }
        @chmod($target, 0444);

        return ['uri' => $relative, 'sha256' => $sha, 'size' => strlen($contents)];
    }

    /** Copia un fichero (p. ej. una carga) a una ruta inmutable verificando su hash. */
    public function importImmutable(string $sourcePath, string $relative, string $expectedSha): void
    {
        $target = $this->path($relative);
        $this->ensureDir(dirname($target));
        if (is_file($target)) {
            if (hash_file('sha256', $target) !== $expectedSha) {
                throw new VulnixException('STORAGE_CONFLICT', 'Conflicto de integridad en el almacén de artefactos.', 500);
            }

            return; // deduplicado por contenido
        }
        $tmp = $target.'.tmp-'.bin2hex(random_bytes(6));
        if (! copy($sourcePath, $tmp) || hash_file('sha256', $tmp) !== $expectedSha || ! rename($tmp, $target)) {
            @unlink($tmp);
            throw new VulnixException('STORAGE_WRITE_FAILED', 'No se pudo almacenar el artefacto de forma íntegra.', 500);
        }
        @chmod($target, 0444);
    }

    public function sha256(string $relative): ?string
    {
        $path = $this->path($relative);

        return is_file($path) ? hash_file('sha256', $path) : null;
    }

    public function read(string $relative): string
    {
        $path = $this->path($relative);
        if (! is_file($path)) {
            throw new VulnixException('STORAGE_NOT_FOUND', 'El fichero solicitado no existe.', 404);
        }

        return (string) file_get_contents($path);
    }

    private function ensureDir(string $dir): void
    {
        if (! is_dir($dir) && ! @mkdir($dir, 0750, true) && ! is_dir($dir)) {
            throw new VulnixException('STORAGE_WRITE_FAILED', 'No se pudo crear el directorio de almacenamiento.', 500);
        }
    }
}
