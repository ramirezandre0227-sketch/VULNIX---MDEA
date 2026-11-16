<?php

namespace App\Enums;

enum DecisionResult: string
{
    case Approved = 'APPROVED';
    case Rejected = 'REJECTED';
    case ReviewRequired = 'REVIEW_REQUIRED';
    case Inconclusive = 'INCONCLUSIVE';
}
