<?php

namespace App\Enums;

/** Solo SUCCEEDED cuenta como control ejecutado. FAILED/TIMED_OUT/SKIPPED nunca equivalen a PASS. */
enum JobStatus: string
{
    case Queued = 'QUEUED';
    case Running = 'RUNNING';
    case Succeeded = 'SUCCEEDED';
    case Failed = 'FAILED';
    case TimedOut = 'TIMED_OUT';
    case Cancelled = 'CANCELLED';
    case Skipped = 'SKIPPED';

    public function isTerminal(): bool
    {
        return ! in_array($this, [self::Queued, self::Running], true);
    }
}
