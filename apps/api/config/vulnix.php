<?php

$root = dirname(base_path(), 2); // raíz del monorepo vulnix/

$resolve = static function (?string $path, string $default) use ($root): string {
    $path = $path ?: $default;
    // Rutas relativas se resuelven respecto a apps/api (base_path) para que tests y CLI coincidan.
    if (! preg_match('#^([A-Za-z]:[\\\\/]|/|\\\\\\\\)#', $path)) {
        $path = base_path($path);
    }

    return rtrim(str_replace('\\', '/', $path), '/');
};

return [
    /*
    | Directorio de datos compartido con el orquestador (artefactos, evidencias, reportes, decisiones).
    | Los artefactos son inmutables y se direccionan por SHA-256.
    */
    'data_dir' => $resolve(env('VULNIX_DATA_DIR'), $root.'/var/data'),

    // Claves de firma Ed25519. Solo la API las lee: los workers nunca tienen acceso.
    'keys_dir' => $resolve(env('VULNIX_KEYS_DIR'), 'storage/app/keys'),

    // Frontend estático (apps/web) servido por la API en el mismo origen (cookies + CSRF).
    'web_root' => $resolve(env('VULNIX_WEB_ROOT'), $root.'/apps/web'),

    // Políticas versionadas en YAML (fuente) que se sincronizan a la base de datos.
    'policies_dir' => $resolve(env('VULNIX_POLICIES_DIR'), $root.'/policies'),

    'issuer' => env('VULNIX_ISSUER', 'vulnix-local'),

    // Vigencia de la autorización de despliegue firmada.
    'authorization_ttl_hours' => (int) env('VULNIX_AUTHORIZATION_TTL_HOURS', 168),

    // Vigencia máxima de una excepción (días).
    'exception_max_days' => (int) env('VULNIX_EXCEPTION_MAX_DAYS', 90),

    // Token de servicio para llamadas internas orquestador -> API (solo /internal/*).
    'internal_token' => env('VULNIX_INTERNAL_TOKEN'),
    'internal_allowed_ips' => array_filter(explode(',', env('VULNIX_INTERNAL_ALLOWED_IPS', '127.0.0.1,::1'))),

    // Servicio interno de analizadores (FastAPI) para salud y catálogo.
    'analyzer_api_url' => env('VULNIX_ANALYZER_API_URL', 'http://127.0.0.1:8100'),

    /*
    | Límites de ingesta (manual §8: validar rutas, tamaños, tipos, enlaces y razón de compresión).
    */
    'ingest' => [
        'max_upload_bytes' => (int) env('VULNIX_MAX_UPLOAD_MB', 40) * 1024 * 1024,
        'max_uncompressed_bytes' => (int) env('VULNIX_MAX_UNCOMPRESSED_MB', 500) * 1024 * 1024,
        'max_file_bytes' => (int) env('VULNIX_MAX_FILE_MB', 50) * 1024 * 1024,
        'max_files' => (int) env('VULNIX_MAX_FILES', 20000),
        'max_ratio' => (int) env('VULNIX_MAX_COMPRESSION_RATIO', 100),
        'max_path_length' => 1024,
        'max_depth' => 48,
        // Extensiones aceptadas para la carga de un archivo individual (no ZIP).
        'single_file_extensions' => ['php', 'phtml', 'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'html', 'htm', 'css', 'json', 'vue'],
    ],

    // Destinos DAST de laboratorio autorizados (manual §8: nunca producción).
    'dast_allowed_targets' => array_filter(explode(',', env('VULNIX_DAST_ALLOWED_TARGETS', ''))),

    // Perfil por defecto cuando el proyecto no define uno.
    'default_profile' => env('VULNIX_DEFAULT_PROFILE', 'web-development'),

    // Login: bloqueo progresivo.
    'auth' => [
        'max_failed_logins' => 5,
        'lockout_minutes' => 15,
        'token_ttl_minutes' => (int) env('VULNIX_API_TOKEN_TTL_MINUTES', 480),
    ],
];
