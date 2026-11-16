<?php

namespace App\Services\Policy;

use App\Exceptions\VulnixException;
use App\Support\Canonical;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * Parsea y valida políticas versionadas (manual §7). Normaliza a una estructura canónica cuyo
 * SHA-256 queda ligado a cada decisión. Una política no puede desactivar fail_closed.
 */
final class PolicyLoader
{
    public const CATEGORIES = ['sast', 'sca', 'secrets', 'quality', 'dast'];

    private const TOP_LEVEL = ['policy', 'version', 'description', 'required', 'analyzers', 'optional_analyzers',
        'security', 'quality', 'intelligence', 'fail_closed'];

    /** @return array{code:string, version:string, rules:array, sha256:string, source:string} */
    public function fromYaml(string $yaml): array
    {
        if (strlen($yaml) > 65536) {
            throw $this->invalid('La política excede el tamaño máximo.');
        }
        try {
            $data = Yaml::parse($yaml, Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE);
        } catch (ParseException $e) {
            throw $this->invalid('YAML inválido: '.$e->getMessage());
        }
        if (! is_array($data)) {
            throw $this->invalid('La política debe ser un mapa YAML.');
        }
        // "version: 1.0" se interpreta como float en YAML: se toma el literal del documento.
        if (isset($data['version']) && ! is_string($data['version'])
            && preg_match('/^version:\s*["\']?([0-9A-Za-z._-]+)["\']?\s*(#.*)?$/m', $yaml, $m)) {
            $data['version'] = $m[1];
        }

        $rules = $this->validate($data);

        return [
            'code' => $rules['policy'],
            'version' => $rules['version'],
            'rules' => $rules,
            'sha256' => Canonical::sha256($rules),
            'source' => $yaml,
        ];
    }

    public function validate(array $data): array
    {
        $unknown = array_diff(array_keys($data), self::TOP_LEVEL);
        if ($unknown) {
            throw $this->invalid('Claves no reconocidas: '.implode(', ', $unknown));
        }
        $code = $data['policy'] ?? null;
        if (! is_string($code) || ! preg_match('/^[a-z0-9-]{3,64}$/', $code)) {
            throw $this->invalid('"policy" debe ser un identificador [a-z0-9-]{3,64}.');
        }
        $version = $data['version'] ?? null;
        if (is_int($version)) {
            $version = (string) $version;
        }
        if (! is_string($version) || ! preg_match('/^[0-9A-Za-z._-]{1,32}$/', $version)) {
            throw $this->invalid('"version" es obligatoria y debe ser alfanumérica.');
        }
        if (($data['fail_closed'] ?? null) !== true) {
            throw $this->invalid('"fail_closed: true" es obligatorio: VULNIX no admite políticas fail-open.');
        }

        $required = $data['required'] ?? null;
        if (! is_array($required) || ! array_is_list($required) || $required === []
            || array_diff($required, self::CATEGORIES) || count(array_unique($required)) !== count($required)) {
            throw $this->invalid('"required" debe ser una lista no vacía de: '.implode(', ', self::CATEGORIES));
        }

        $analyzers = $data['analyzers'] ?? [];
        if (! is_array($analyzers)) {
            throw $this->invalid('"analyzers" debe ser un mapa categoría -> lista de analizadores.');
        }
        $normalizedAnalyzers = [];
        foreach ($required as $category) {
            $list = $analyzers[$category] ?? null;
            if (! is_array($list) || $list === [] || ! array_is_list($list)) {
                throw $this->invalid("La categoría obligatoria \"{$category}\" necesita al menos un analizador en \"analyzers\".");
            }
            foreach ($list as $name) {
                $this->assertAnalyzerName($name);
            }
            $normalizedAnalyzers[$category] = array_values(array_unique($list));
        }
        if (array_diff(array_keys($analyzers), $required)) {
            throw $this->invalid('"analyzers" solo puede definir categorías incluidas en "required".');
        }

        $optional = $data['optional_analyzers'] ?? [];
        if (! is_array($optional) || ! array_is_list($optional)) {
            throw $this->invalid('"optional_analyzers" debe ser una lista.');
        }
        foreach ($optional as $name) {
            $this->assertAnalyzerName($name);
        }

        $security = $data['security'] ?? [];
        $sec = [
            'max_confirmed_critical' => $this->nonNegativeInt($security, 'max_confirmed_critical', 0),
            'max_confirmed_high' => $this->nonNegativeInt($security, 'max_confirmed_high', 0),
            'block_exposed_secrets' => $this->bool($security, 'block_exposed_secrets', true),
            'review_uncertain_findings' => $this->bool($security, 'review_uncertain_findings', true),
        ];

        $quality = $data['quality'] ?? [];
        $coverage = $quality['min_line_coverage'] ?? 0;
        if (! is_int($coverage) && ! is_float($coverage) || $coverage < 0 || $coverage > 100) {
            throw $this->invalid('"quality.min_line_coverage" debe estar entre 0 y 100.');
        }
        $qa = [
            'require_build_pass' => $this->bool($quality, 'require_build_pass', true),
            'require_tests_pass' => $this->bool($quality, 'require_tests_pass', false),
            'min_line_coverage' => $coverage,
        ];

        $intel = $data['intelligence'] ?? [];
        $maxAge = $intel['max_age_days'] ?? null;
        if (in_array('sca', $required, true) && (! is_int($maxAge) || $maxAge < 1 || $maxAge > 365)) {
            throw $this->invalid('"intelligence.max_age_days" (1-365) es obligatorio cuando se exige SCA.');
        }

        $description = $data['description'] ?? null;
        if ($description !== null && (! is_string($description) || mb_strlen($description) > 500)) {
            throw $this->invalid('"description" debe ser texto de hasta 500 caracteres.');
        }

        return [
            'policy' => $code,
            'version' => $version,
            'description' => $description,
            'required' => array_values($required),
            'analyzers' => $normalizedAnalyzers,
            'optional_analyzers' => array_values(array_unique($optional)),
            'security' => $sec,
            'quality' => $qa,
            'intelligence' => ['max_age_days' => is_int($maxAge) ? $maxAge : 7],
            'fail_closed' => true,
        ];
    }

    private function assertAnalyzerName(mixed $name): void
    {
        if (! is_string($name) || ! preg_match('/^[a-z0-9-]{2,64}$/', $name)) {
            throw $this->invalid('Nombre de analizador inválido.');
        }
    }

    private function nonNegativeInt(array $data, string $key, int $default): int
    {
        $value = $data[$key] ?? $default;
        if (! is_int($value) || $value < 0) {
            throw $this->invalid("\"{$key}\" debe ser un entero >= 0.");
        }

        return $value;
    }

    private function bool(array $data, string $key, bool $default): bool
    {
        $value = $data[$key] ?? $default;
        if (! is_bool($value)) {
            throw $this->invalid("\"{$key}\" debe ser booleano.");
        }

        return $value;
    }

    private function invalid(string $message): VulnixException
    {
        return new VulnixException('POLICY_INVALID', $message, 422);
    }
}
