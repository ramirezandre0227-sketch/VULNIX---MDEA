<?php

namespace App\Services\Signing;

use App\Exceptions\VulnixException;
use App\Support\Canonical;

/**
 * Firma de decisiones como JWS compacto EdDSA (Ed25519, RFC 8037).
 * Sin clave de firma no se emite ninguna decisión (fail closed).
 */
final class DecisionSigner
{
    public const TYP = 'vulnix-deploy-authz+jwt';

    public function keysDir(): string
    {
        return config('vulnix.keys_dir');
    }

    public function hasKeys(): bool
    {
        return is_file($this->keysDir().'/ed25519.key') && is_file($this->keysDir().'/ed25519.pub');
    }

    /** @return array{key_id:string, public_key:string} */
    public function generateKeys(bool $force = false): array
    {
        if ($this->hasKeys() && ! $force) {
            throw new VulnixException('SIGNING_KEY_EXISTS', 'Ya existe un par de claves; use --force para rotarlo.', 409);
        }
        $dir = $this->keysDir();
        if (! is_dir($dir) && ! mkdir($dir, 0700, true) && ! is_dir($dir)) {
            throw new VulnixException('SIGNING_KEY_WRITE_FAILED', 'No se pudo crear el directorio de claves.', 500);
        }
        if ($force && $this->hasKeys()) {
            $old = $this->keyId();
            @chmod($dir.'/ed25519.key', 0600);
            rename($dir.'/ed25519.key', $dir."/retired-{$old}.key");
            rename($dir.'/ed25519.pub', $dir."/retired-{$old}.pub");
        }
        $pair = sodium_crypto_sign_keypair();
        file_put_contents($dir.'/ed25519.key', base64_encode(sodium_crypto_sign_secretkey($pair)), LOCK_EX);
        file_put_contents($dir.'/ed25519.pub', base64_encode(sodium_crypto_sign_publickey($pair)), LOCK_EX);
        @chmod($dir.'/ed25519.key', 0400);
        sodium_memzero($pair);

        return ['key_id' => $this->keyId(), 'public_key' => $this->publicKeyB64()];
    }

    public function publicKeyB64(): string
    {
        $this->assertKeys();

        return trim((string) file_get_contents($this->keysDir().'/ed25519.pub'));
    }

    public function keyId(): string
    {
        return substr(hash('sha256', base64_decode($this->publicKeyB64(), true) ?: ''), 0, 16);
    }

    public function sign(array $claims): string
    {
        $this->assertKeys();
        $secret = base64_decode(trim((string) file_get_contents($this->keysDir().'/ed25519.key')), true);
        if ($secret === false || strlen($secret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new VulnixException('SIGNING_KEY_INVALID', 'La clave de firma es inválida.', 500);
        }
        $header = ['alg' => 'EdDSA', 'typ' => self::TYP, 'kid' => $this->keyId()];
        $input = Canonical::base64url(Canonical::json($header)).'.'.Canonical::base64url(Canonical::json($claims));
        $signature = sodium_crypto_sign_detached($input, $secret);
        sodium_memzero($secret);

        return $input.'.'.Canonical::base64url($signature);
    }

    /**
     * Verificación completa para el gate de despliegue.
     *
     * @return array{valid: bool, errors: list<string>, claims: ?array}
     */
    public function verify(string $token, ?string $artifactSha256 = null, ?int $now = null, ?string $publicKeyB64 = null): array
    {
        $now ??= time();
        $errors = [];
        $parts = explode('.', trim($token));
        if (count($parts) !== 3) {
            return ['valid' => false, 'errors' => ['MALFORMED_TOKEN'], 'claims' => null];
        }
        [$h, $p, $s] = $parts;
        $header = json_decode((string) Canonical::base64urlDecode($h), true);
        $claims = json_decode((string) Canonical::base64urlDecode($p), true);
        $signature = Canonical::base64urlDecode($s);
        if (! is_array($header) || ! is_array($claims) || $signature === false) {
            return ['valid' => false, 'errors' => ['MALFORMED_TOKEN'], 'claims' => null];
        }
        if (($header['alg'] ?? null) !== 'EdDSA' || ($header['typ'] ?? null) !== self::TYP) {
            return ['valid' => false, 'errors' => ['UNSUPPORTED_ALGORITHM'], 'claims' => $claims];
        }
        $pub = base64_decode($publicKeyB64 ?? $this->publicKeyB64(), true);
        if ($pub === false || strlen($pub) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return ['valid' => false, 'errors' => ['PUBLIC_KEY_INVALID'], 'claims' => $claims];
        }
        if (($header['kid'] ?? null) !== substr(hash('sha256', $pub), 0, 16)) {
            $errors[] = 'KEY_ID_MISMATCH';
        }
        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES || ! sodium_crypto_sign_verify_detached($signature, "{$h}.{$p}", $pub)) {
            return ['valid' => false, 'errors' => ['SIGNATURE_INVALID'], 'claims' => $claims];
        }
        if (($claims['iss'] ?? null) !== config('vulnix.issuer')) {
            $errors[] = 'ISSUER_MISMATCH';
        }
        if (! is_int($claims['exp'] ?? null) || $claims['exp'] <= $now) {
            $errors[] = 'EXPIRED';
        }
        if (($claims['result'] ?? null) !== 'APPROVED') {
            $errors[] = 'NOT_APPROVED';
        }
        if ($artifactSha256 !== null && ! hash_equals((string) ($claims['artifact_sha256'] ?? ''), strtolower($artifactSha256))) {
            $errors[] = 'ARTIFACT_HASH_MISMATCH';
        }

        return ['valid' => $errors === [], 'errors' => $errors, 'claims' => $claims];
    }

    private function assertKeys(): void
    {
        if (! $this->hasKeys()) {
            throw new VulnixException('SIGNING_KEY_MISSING',
                'No hay clave de firma configurada: no se emiten decisiones (fail closed). Ejecute php artisan vulnix:keys:generate.', 503);
        }
    }
}
