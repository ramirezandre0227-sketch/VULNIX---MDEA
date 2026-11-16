<?php

namespace App\Services\Ingest;

use App\Exceptions\VulnixException;
use ZipArchive;

/**
 * Inspección de ZIP bajo supuesto de entrada adversarial, SIN extraer al disco.
 * Rechaza: ZIP Slip / traversal, rutas absolutas o de unidad, enlaces simbólicos y ficheros especiales,
 * entradas cifradas, nombres reservados de Windows, ADS, duplicados (incl. colisión por mayúsculas),
 * bombas de compresión (ratio global y por entrada), exceso de ficheros/tamaño/profundidad.
 * Los tamaños declarados en cabecera NO se confían: se cuentan los bytes reales al calcular hashes.
 */
final class ZipInspector
{
    private const S_IFMT = 0170000;
    private const S_IFREG = 0100000;
    private const S_IFDIR = 0040000;
    private const WINDOWS_RESERVED = '/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$/i';

    public function __construct(private readonly array $limits) {}

    /**
     * @return array{files: list<array{path:string,size:int,sha256:string}>, total_bytes:int, nested_archives: list<string>}
     */
    public function inspect(string $zipPath): array
    {
        $archiveSize = filesize($zipPath) ?: 0;
        $zip = new ZipArchive;
        $rc = $zip->open($zipPath, ZipArchive::RDONLY | ZipArchive::CHECKCONS);
        if ($rc !== true) {
            throw $this->reject('ZIP_INVALID', 'El archivo no es un ZIP válido o está corrupto.', ['zip_error' => $rc]);
        }

        try {
            $count = $zip->numFiles;
            if ($count === 0) {
                throw $this->reject('ZIP_EMPTY', 'El ZIP no contiene ficheros.');
            }
            if ($count > $this->limits['max_files']) {
                throw $this->reject('ZIP_TOO_MANY_FILES', 'El ZIP excede el número máximo de ficheros.', ['max' => $this->limits['max_files']]);
            }

            $seen = [];
            $declaredTotal = 0;
            $entries = [];
            for ($i = 0; $i < $count; $i++) {
                $stat = $zip->statIndex($i, ZipArchive::FL_UNCHANGED);
                if ($stat === false) {
                    throw $this->reject('ZIP_INVALID', 'Entrada ZIP ilegible.');
                }
                $name = (string) $stat['name'];
                $path = $this->validatePath($name);
                $isDir = str_ends_with($path, '/');

                if (($stat['encryption_method'] ?? 0) !== 0) {
                    throw $this->reject('ZIP_ENCRYPTED_ENTRY', 'El ZIP contiene entradas cifradas.', ['path' => $path]);
                }

                $opsys = 0;
                $attr = 0;
                if ($zip->getExternalAttributesIndex($i, $opsys, $attr, ZipArchive::FL_UNCHANGED) && $opsys === ZipArchive::OPSYS_UNIX) {
                    $mode = ($attr >> 16) & 0xFFFF;
                    $type = $mode & self::S_IFMT;
                    if ($type !== 0 && $type !== self::S_IFREG && $type !== self::S_IFDIR) {
                        throw $this->reject('ZIP_SPECIAL_ENTRY', 'El ZIP contiene enlaces simbólicos o ficheros especiales.', ['path' => $path]);
                    }
                }

                $key = mb_strtolower(rtrim($path, '/'));
                if (isset($seen[$key])) {
                    throw $this->reject('ZIP_DUPLICATE_ENTRY', 'El ZIP contiene rutas duplicadas o que colisionan.', ['path' => $path]);
                }
                $seen[$key] = true;

                if ($isDir) {
                    continue;
                }

                $size = (int) $stat['size'];
                $compSize = (int) $stat['comp_size'];
                if ($size > $this->limits['max_file_bytes']) {
                    throw $this->reject('ZIP_FILE_TOO_LARGE', 'Un fichero del ZIP excede el tamaño máximo.', ['path' => $path]);
                }
                if ($size > 1048576 && $compSize > 0 && intdiv($size, max($compSize, 1)) > $this->limits['max_ratio']) {
                    throw $this->reject('ZIP_BOMB_SUSPECTED', 'Razón de compresión anómala (posible bomba ZIP).', ['path' => $path]);
                }
                $declaredTotal += $size;
                if ($declaredTotal > $this->limits['max_uncompressed_bytes']) {
                    throw $this->reject('ZIP_TOO_LARGE', 'El contenido descomprimido excede el máximo permitido.');
                }
                $entries[] = ['index' => $i, 'path' => $path, 'declared' => $size];
            }

            if ($archiveSize > 0 && $declaredTotal > 1048576 && intdiv($declaredTotal, $archiveSize) > $this->limits['max_ratio']) {
                throw $this->reject('ZIP_BOMB_SUSPECTED', 'Razón de compresión global anómala (posible bomba ZIP).');
            }

            // Hash por fichero contando bytes reales (las cabeceras pueden mentir).
            $files = [];
            $nested = [];
            $realTotal = 0;
            foreach ($entries as $entry) {
                $stream = $zip->getStreamIndex($entry['index'], ZipArchive::FL_UNCHANGED);
                if ($stream === false) {
                    throw $this->reject('ZIP_INVALID', 'No se pudo leer una entrada del ZIP.', ['path' => $entry['path']]);
                }
                $ctx = hash_init('sha256');
                $bytes = 0;
                while (! feof($stream)) {
                    $chunk = fread($stream, 65536);
                    if ($chunk === false) {
                        fclose($stream);
                        throw $this->reject('ZIP_INVALID', 'Error al leer una entrada del ZIP.', ['path' => $entry['path']]);
                    }
                    $bytes += strlen($chunk);
                    if ($bytes > $entry['declared'] || $bytes > $this->limits['max_file_bytes']) {
                        fclose($stream);
                        throw $this->reject('ZIP_SIZE_MISMATCH', 'El tamaño real de una entrada no coincide con su cabecera.', ['path' => $entry['path']]);
                    }
                    hash_update($ctx, $chunk);
                }
                fclose($stream);
                if ($bytes !== $entry['declared']) {
                    throw $this->reject('ZIP_SIZE_MISMATCH', 'El tamaño real de una entrada no coincide con su cabecera.', ['path' => $entry['path']]);
                }
                $realTotal += $bytes;
                if (preg_match('/\.(zip|jar|war|tar|gz|tgz|7z|rar|phar)$/i', $entry['path'])) {
                    $nested[] = $entry['path'];
                }
                $files[] = ['path' => $entry['path'], 'size' => $bytes, 'sha256' => hash_final($ctx)];
            }

            usort($files, fn ($a, $b) => strcmp($a['path'], $b['path']));

            return ['files' => $files, 'total_bytes' => $realTotal, 'nested_archives' => $nested];
        } finally {
            $zip->close();
        }
    }

    /** Lee un fichero pequeño del ZIP (p. ej. package.json) con límite de tamaño. */
    public function readSmall(string $zipPath, string $path, int $maxBytes = 1048576): ?string
    {
        $zip = new ZipArchive;
        if ($zip->open($zipPath, ZipArchive::RDONLY) !== true) {
            return null;
        }
        try {
            $index = $zip->locateName($path);
            if ($index === false) {
                return null;
            }
            $stat = $zip->statIndex($index);
            if (! $stat || $stat['size'] > $maxBytes) {
                return null;
            }
            $data = $zip->getFromIndex($index, $maxBytes);

            return $data === false ? null : $data;
        } finally {
            $zip->close();
        }
    }

    public function validatePath(string $name): string
    {
        if ($name === '' || str_contains($name, "\0") || preg_match('/[\x00-\x1F\x7F]/', $name)) {
            throw $this->reject('ZIP_PATH_INVALID', 'El ZIP contiene nombres de fichero inválidos.');
        }
        if (! mb_check_encoding($name, 'UTF-8')) {
            throw $this->reject('ZIP_PATH_INVALID', 'El ZIP contiene nombres con codificación inválida.');
        }
        // Algunas herramientas de Windows usan "\" como separador: se normaliza ANTES de validar
        // (el extractor del worker aplica exactamente la misma normalización).
        $name = str_replace('\\', '/', $name);
        if (str_starts_with($name, '/') || preg_match('/^[A-Za-z]:/', $name)) {
            throw $this->reject('ZIP_PATH_TRAVERSAL', 'El ZIP contiene rutas absolutas.', ['path' => $name]);
        }
        if (mb_strlen($name) > $this->limits['max_path_length']) {
            throw $this->reject('ZIP_PATH_INVALID', 'El ZIP contiene rutas demasiado largas.');
        }
        $segments = explode('/', rtrim($name, '/'));
        if (count($segments) > $this->limits['max_depth']) {
            throw $this->reject('ZIP_PATH_INVALID', 'El ZIP excede la profundidad máxima de directorios.');
        }
        foreach ($segments as $segment) {
            if ($segment === '..' || $segment === '.' || $segment === '') {
                throw $this->reject('ZIP_PATH_TRAVERSAL', 'El ZIP contiene rutas con recorrido de directorios (ZIP Slip).', ['path' => $name]);
            }
            if (str_contains($segment, ':')) {
                throw $this->reject('ZIP_PATH_INVALID', 'El ZIP contiene nombres con ":" (flujos alternativos).', ['path' => $name]);
            }
            if (preg_match(self::WINDOWS_RESERVED, $segment) || preg_match('/[ .]$/', $segment)) {
                throw $this->reject('ZIP_PATH_INVALID', 'El ZIP contiene nombres reservados o ambiguos.', ['path' => $name]);
            }
        }

        return $name;
    }

    private function reject(string $code, string $message, array $details = []): VulnixException
    {
        return new VulnixException($code, $message, 422, $details);
    }
}
