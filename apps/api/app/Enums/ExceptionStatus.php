<?php

namespace App\Enums;

enum ExceptionStatus: string
{
    case Pending = 'PENDING';
    case Approved = 'APPROVED';
    case Rejected = 'REJECTED';
    case Revoked = 'REVOKED';
}
