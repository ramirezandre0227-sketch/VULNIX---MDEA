<?php

namespace App\Support;

/** JSON canónico (claves ordenadas, sin escapes ambiguos) para hashes reproducibles. */
final class Canonical
{
    public static function json(mixed $value): string
    {
        return json_encode(self::normalize($value), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    public static function sha256(mixed $value): string
    {
        return hash('sha256', self::json($value));
    }

    private static function normalize(mixed $value): mixed
    {
        if (is_array($value)) {
            if (array_is_list($value)) {
                return array_map([self::class, 'normalize'], $value);
            }
            ksort($value, SORT_STRING);

            return (object) array_map([self::class, 'normalize'], $value);
        }

        return $value;
    }

    public static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function base64urlDecode(string $text): string|false
    {
        if (! preg_match('/^[A-Za-z0-9_-]*$/', $text)) {
            return false;
        }
        $pad = strlen($text) % 4;
        if ($pad) {
            $text .= str_repeat('=', 4 - $pad);
        }

        return base64_decode(strtr($text, '-_', '+/'), true);
    }
}
