<?php

namespace App\Services\Ingest;

/**
 * Detección tecnológica (manual §4): lenguajes, frameworks, manifiestos y lockfiles,
 * a partir del inventario y de manifiestos leídos con límite de tamaño.
 */
final class TechnologyDetector
{
    private const LANGUAGE_BY_EXT = [
        'php' => 'php', 'phtml' => 'php',
        'js' => 'javascript', 'mjs' => 'javascript', 'cjs' => 'javascript', 'jsx' => 'javascript',
        'ts' => 'typescript', 'tsx' => 'typescript',
        'html' => 'html', 'htm' => 'html', 'vue' => 'javascript',
        'css' => 'css', 'scss' => 'css',
    ];

    private const MANIFESTS = ['composer.json', 'package.json'];

    private const LOCKFILES = ['composer.lock', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'];

    /**
     * @param  list<array{path:string,size:int,sha256:string}>  $files
     * @param  callable(string):?string  $reader  lector acotado de ficheros del artefacto
     */
    public function detect(array $files, callable $reader): array
    {
        $languages = [];
        $manifests = [];
        $lockfiles = [];
        $vendored = 0;
        foreach ($files as $file) {
            $path = $file['path'];
            if (preg_match('#(^|/)(node_modules|vendor)/#', $path)) {
                $vendored++;

                continue;
            }
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if (str_ends_with(strtolower($path), '.blade.php')) {
                $languages['php'] = ($languages['php'] ?? 0) + 1;
            } elseif (isset(self::LANGUAGE_BY_EXT[$ext])) {
                $lang = self::LANGUAGE_BY_EXT[$ext];
                $languages[$lang] = ($languages[$lang] ?? 0) + 1;
            }
            $base = basename($path);
            if (in_array($base, self::MANIFESTS, true)) {
                $manifests[] = $path;
            }
            if (in_array($base, self::LOCKFILES, true)) {
                $lockfiles[] = $path;
            }
        }
        arsort($languages);

        $frameworks = [];
        foreach ($manifests as $manifest) {
            $json = json_decode((string) $reader($manifest), true);
            if (! is_array($json)) {
                continue;
            }
            if (basename($manifest) === 'composer.json') {
                $deps = array_merge($json['require'] ?? [], $json['require-dev'] ?? []);
                if (isset($deps['laravel/framework'])) {
                    $frameworks[] = 'laravel';
                }
                if (isset($deps['symfony/framework-bundle'])) {
                    $frameworks[] = 'symfony';
                }
            } else {
                $deps = array_merge($json['dependencies'] ?? [], $json['devDependencies'] ?? []);
                foreach (['react' => 'react', 'vue' => 'vue', 'next' => 'nextjs', 'express' => 'express',
                    '@angular/core' => 'angular', 'svelte' => 'svelte', 'typescript' => 'typescript'] as $dep => $fw) {
                    if (isset($deps[$dep])) {
                        $frameworks[] = $fw;
                    }
                }
            }
        }

        $hasManifestWithoutLock = [];
        foreach ($manifests as $manifest) {
            $dir = dirname($manifest) === '.' ? '' : dirname($manifest).'/';
            $expected = basename($manifest) === 'composer.json'
                ? [$dir.'composer.lock']
                : [$dir.'package-lock.json', $dir.'npm-shrinkwrap.json', $dir.'yarn.lock', $dir.'pnpm-lock.yaml'];
            if (! array_intersect($expected, $lockfiles)) {
                $hasManifestWithoutLock[] = $manifest;
            }
        }

        return [
            'languages' => $languages,
            'primary_language' => array_key_first($languages),
            'frameworks' => array_values(array_unique($frameworks)),
            'manifests' => $manifests,
            'lockfiles' => $lockfiles,
            'manifests_without_lockfile' => $hasManifestWithoutLock,
            'vendored_files' => $vendored,
        ];
    }
}
