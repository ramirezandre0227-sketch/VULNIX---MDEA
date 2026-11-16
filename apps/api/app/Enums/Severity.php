<?php

namespace App\Enums;

enum Severity: string
{
    case Critical = 'CRITICAL';
    case High = 'HIGH';
    case Medium = 'MEDIUM';
    case Low = 'LOW';
    case Info = 'INFO';

    public function rank(): int
    {
        return match ($this) {
            self::Critical => 5, self::High => 4, self::Medium => 3, self::Low => 2, self::Info => 1,
        };
    }

    public function sarifLevel(): string
    {
        return match ($this) {
            self::Critical, self::High => 'error',
            self::Medium => 'warning',
            default => 'note',
        };
    }
}
