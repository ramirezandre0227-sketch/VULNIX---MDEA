<?php

namespace App\Enums;

/**
 * Máquina de estados del análisis (manual §2). COMPLETED significa que el proceso terminó,
 * no que el proyecto esté aprobado: la decisión se guarda por separado. La base de datos
 * aplica las mismas transiciones mediante trigger (defensa en profundidad).
 */
enum AnalysisStatus: string
{
    case Created = 'CREATED';
    case Validating = 'VALIDATING';
    case Queued = 'QUEUED';
    case Running = 'RUNNING';
    case Normalizing = 'NORMALIZING';
    case Evaluating = 'EVALUATING';
    case Completed = 'COMPLETED';
    case Failed = 'FAILED';
    case Cancelled = 'CANCELLED';
    case TimedOut = 'TIMED_OUT';
    case Inconclusive = 'INCONCLUSIVE';

    /** @return list<self> */
    public function allowedNext(): array
    {
        return match ($this) {
            self::Created => [self::Validating, self::Failed, self::Cancelled],
            self::Validating => [self::Queued, self::Failed, self::Inconclusive, self::Cancelled],
            self::Queued => [self::Running, self::Failed, self::Cancelled, self::TimedOut],
            self::Running => [self::Normalizing, self::Failed, self::Cancelled, self::TimedOut],
            self::Normalizing => [self::Evaluating, self::Failed],
            self::Evaluating => [self::Completed, self::Inconclusive, self::Failed],
            default => [],
        };
    }

    public function canTransitionTo(self $next): bool
    {
        return in_array($next, $this->allowedNext(), true);
    }

    public function isTerminal(): bool
    {
        return in_array($this, [self::Completed, self::Failed, self::Cancelled, self::TimedOut, self::Inconclusive], true);
    }

    /** Estados en los que se puede emitir (o reemitir) una decisión. */
    public function isEvaluable(): bool
    {
        return $this === self::Evaluating || $this->isTerminal();
    }
}
