<?php

namespace App\Http\Controllers\Api;

use App\Enums\ExceptionStatus;
use App\Exceptions\VulnixException;
use App\Http\Controllers\Controller;
use App\Models\Finding;
use App\Models\FindingException;
use App\Support\Access;
use App\Support\Audit;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;

/**
 * Excepciones (manual §13): aprobación por rol, justificación, fecha de vencimiento obligatoria.
 * Ninguna excepción modifica resultados brutos: es una resolución auditable separada.
 */
class ExceptionController extends Controller
{
    public function index(Request $request): JsonResponse
    {
        $user = $request->user();
        $query = FindingException::query()->with('requester', 'approver', 'finding.analysis.version.project')->orderByDesc('created_at');
        if ($status = $request->query('status')) {
            $query->where('status', $status);
        }
        if (! $user->canDo('projects.view_all')) {
            $query->whereHas('finding.analysis.version.project', fn ($q) => $q->where('owner_id', $user->id));
        }
        $page = $query->paginate(min((int) $request->integer('per_page', 50), 100));

        return response()->json([
            'data' => collect($page->items())->map(fn (FindingException $e) => $e->toApiArray() + [
                'finding' => [
                    'title' => $e->finding->title, 'severity' => $e->finding->severity->value, 'rule_id' => $e->finding->rule_id,
                    'file' => $e->finding->file_path, 'line' => $e->finding->start_line, 'analysis_id' => $e->finding->analysis_id,
                ],
                'project' => $e->finding->analysis->version->project->name,
                'can_decide' => $user->canDo('exceptions.decide') && $e->requested_by !== $user->id,
            ]),
            'meta' => ['page' => $page->currentPage(), 'per_page' => $page->perPage(), 'total' => $page->total()],
        ]);
    }

    /** POST /exceptions: solicitud de excepción (queda PENDING). */
    public function store(Request $request): JsonResponse
    {
        $max = config('vulnix.exception_max_days');
        $data = $request->validate([
            'finding_id' => ['required', 'uuid'],
            'kind' => ['required', Rule::in(['FALSE_POSITIVE', 'ACCEPTED_RISK'])],
            'reason' => ['required', 'string', 'min:20', 'max:4000'],
            'expires_at' => ['required', 'date', 'after:now', 'before_or_equal:'.now()->addDays($max)->toDateTimeString()],
        ]);
        $finding = Finding::with('analysis.version.project')->findOrFail($data['finding_id']);
        Access::ensureAnalysis($request->user(), $finding->analysis);
        if (FindingException::where('finding_id', $finding->id)->where('status', 'PENDING')->exists()) {
            throw VulnixException::conflict('EXCEPTION_ALREADY_PENDING', 'Ya existe una solicitud pendiente para este hallazgo.');
        }
        $exception = FindingException::create([
            'finding_id' => $finding->id,
            'requested_by' => $request->user()->id,
            'kind' => $data['kind'],
            'reason' => $data['reason'],
            'expires_at' => $data['expires_at'],
            'status' => ExceptionStatus::Pending->value,
        ]);
        Audit::log('exception.requested', 'exception', $exception->id, [
            'finding_id' => $finding->id, 'fingerprint' => $finding->fingerprint, 'kind' => $data['kind'], 'expires_at' => $data['expires_at'],
        ]);

        return response()->json(['data' => $exception->load('requester')->toApiArray()], 201);
    }

    /** POST /exceptions/{id}/decision: APPROVE | REJECT | REVOKE. Quien la solicitó no puede decidirla. */
    public function decide(Request $request, FindingException $exception): JsonResponse
    {
        $data = $request->validate([
            'decision' => ['required', Rule::in(['APPROVE', 'REJECT', 'REVOKE'])],
            'note' => ['required', 'string', 'min:5', 'max:2000'],
        ]);
        $user = $request->user();
        if ($exception->requested_by === $user->id) {
            throw VulnixException::forbidden('Segregación de funciones: no puede decidir su propia solicitud.');
        }
        $from = $exception->status;
        $to = match ($data['decision']) {
            'APPROVE' => ExceptionStatus::Approved,
            'REJECT' => ExceptionStatus::Rejected,
            'REVOKE' => ExceptionStatus::Revoked,
        };
        $allowed = ($from === ExceptionStatus::Pending && in_array($to, [ExceptionStatus::Approved, ExceptionStatus::Rejected], true))
            || ($from === ExceptionStatus::Approved && $to === ExceptionStatus::Revoked);
        if (! $allowed) {
            throw VulnixException::conflict('EXCEPTION_INVALID_TRANSITION', "No se puede pasar de {$from->value} a {$to->value}.");
        }
        if ($to === ExceptionStatus::Approved && $exception->expires_at->isPast()) {
            throw VulnixException::conflict('EXCEPTION_EXPIRED', 'La excepción ya venció; debe solicitarse de nuevo.');
        }
        $exception->forceFill([
            'status' => $to->value,
            'approver_id' => $user->id,
            'decision_note' => $data['note'],
            'decided_at' => now(),
        ])->save();
        Audit::log('exception.'.strtolower($to->value), 'exception', $exception->id, [
            'from' => $from->value, 'to' => $to->value, 'finding_id' => $exception->finding_id,
        ]);

        return response()->json(['data' => $exception->fresh(['requester', 'approver'])->toApiArray()]);
    }
}
