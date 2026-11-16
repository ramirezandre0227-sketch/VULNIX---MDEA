<?php

namespace App\Exceptions;

use RuntimeException;

/**
 * Error de dominio con código estable (manual §6: "errores con códigos estables").
 * El mensaje es seguro para mostrar al usuario; nunca incluye secretos ni rutas internas.
 */
class VulnixException extends RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly int $status = 422,
        public readonly array $details = [],
    ) {
        parent::__construct($message);
    }

    public static function forbidden(string $message = 'No tiene permisos para esta operación.'): self
    {
        return new self('FORBIDDEN', $message, 403);
    }

    public static function conflict(string $code, string $message, array $details = []): self
    {
        return new self($code, $message, 409, $details);
    }
}
