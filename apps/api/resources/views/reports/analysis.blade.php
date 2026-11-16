<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>VULNIX · Informe {{ $r['project']['name'] }} {{ $r['artifact']['version'] }}</title>
<style>
  body { font-family: "DejaVu Sans", Arial, sans-serif; font-size: 10.5px; color: #0f1d2c; margin: 28px; }
  h1 { font-size: 20px; margin: 0 0 2px; color: #0d2338; }
  h2 { font-size: 13.5px; margin: 22px 0 8px; color: #0d2338; border-bottom: 1px solid #c9d6e2; padding-bottom: 4px; }
  .muted { color: #5b6b7b; }
  table { width: 100%; border-collapse: collapse; margin: 6px 0; }
  th, td { text-align: left; padding: 5px 7px; border-bottom: 1px solid #e1e8ef; vertical-align: top; }
  th { background: #eef4f7; font-weight: bold; font-size: 9.5px; text-transform: uppercase; letter-spacing: .03em; }
  .mono { font-family: "DejaVu Sans Mono", monospace; font-size: 9px; word-break: break-all; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 10px; }
  .APPROVED { background: #dcf3e4; color: #135c2f; } .REJECTED { background: #fbe0e0; color: #8a1c1c; }
  .REVIEW_REQUIRED { background: #fdf0d5; color: #7a4d00; } .INCONCLUSIVE { background: #e6e9ef; color: #3a4556; }
  .sev-CRITICAL { color: #8a1c1c; font-weight: bold; } .sev-HIGH { color: #b03a1a; font-weight: bold; }
  .sev-MEDIUM { color: #8a5a00; } .sev-LOW, .sev-INFO { color: #4a5a6a; }
  .finding { border: 1px solid #e1e8ef; padding: 8px 10px; margin: 8px 0; page-break-inside: avoid; }
  .finding h3 { margin: 0 0 4px; font-size: 11.5px; }
  .note { background: #f5f8fa; border-left: 3px solid #1d6f8c; padding: 6px 10px; margin: 8px 0; }
</style>
</head>
<body>
  <h1>VULNIX · Informe de evaluación</h1>
  <div class="muted">Generado {{ $r['generated_at'] }} · Esquema {{ $r['schema'] }}</div>

  <h2>Decisión</h2>
  @if ($r['decision'])
    <p><span class="badge {{ $r['decision']['result'] }}">{{ $r['decision']['result'] }}</span>
       &nbsp;emitida {{ $r['decision']['issued_at'] }} · vence {{ $r['decision']['expires_at'] }} · clave {{ $r['decision']['key_id'] }}</p>
    @if (count($r['decision']['reasons']))
      <table>
        <tr><th>Resultado</th><th>Código</th><th>Motivo</th></tr>
        @foreach ($r['decision']['reasons'] as $reason)
          <tr><td>{{ $reason['outcome'] }}</td><td class="mono">{{ $reason['code'] }}</td><td>{{ $reason['message'] }}</td></tr>
        @endforeach
      </table>
    @else
      <p>Todos los controles obligatorios se cumplieron.</p>
    @endif
  @else
    <p class="muted">Aún no se ha emitido una decisión para este análisis.</p>
  @endif

  <h2>Artefacto y política</h2>
  <table>
    <tr><th>Proyecto</th><td>{{ $r['project']['name'] }} (criticidad {{ $r['project']['criticality'] }})</td></tr>
    <tr><th>Versión</th><td>{{ $r['artifact']['version'] }} · {{ $r['artifact']['filename'] }} · {{ number_format($r['artifact']['size_bytes']) }} bytes · {{ $r['artifact']['files'] }} ficheros</td></tr>
    <tr><th>SHA-256 artefacto</th><td class="mono">{{ $r['artifact']['sha256'] }}</td></tr>
    <tr><th>Análisis</th><td class="mono">{{ $r['analysis']['id'] }} · {{ $r['analysis']['status'] }}</td></tr>
    <tr><th>Política</th><td>{{ $r['policy']['code'] }} v{{ $r['policy']['version'] }}</td></tr>
    <tr><th>SHA-256 política</th><td class="mono">{{ $r['policy']['sha256'] }}</td></tr>
  </table>

  <h2>Controles ejecutados</h2>
  <table>
    <tr><th>Analizador</th><th>Categoría</th><th>Obligatorio</th><th>Versión</th><th>Estado</th><th>Detalle</th></tr>
    @foreach ($r['jobs'] as $job)
      <tr>
        <td>{{ $job['analyzer'] }}</td><td>{{ $job['category'] }}</td><td>{{ $job['mandatory'] ? 'Sí' : 'No' }}</td>
        <td class="mono">{{ $job['analyzer_version'] ?? '—' }}</td><td>{{ $job['status'] }}</td>
        <td>{{ $job['error_type'] ? $job['error_type'].': '.\Illuminate\Support\Str::limit((string) $job['error_message'], 140) : '' }}</td>
      </tr>
    @endforeach
  </table>

  <h2>Resumen de hallazgos ({{ $r['summary']['total'] }})</h2>
  <table>
    <tr>@foreach ($r['summary']['by_severity'] as $sev => $n)<th>{{ $sev }}</th>@endforeach</tr>
    <tr>@foreach ($r['summary']['by_severity'] as $sev => $n)<td class="sev-{{ $sev }}">{{ $n }}</td>@endforeach</tr>
  </table>

  <h2>Hallazgos</h2>
  @forelse ($r['findings'] as $f)
    <div class="finding">
      <h3><span class="sev-{{ $f['severity'] }}">[{{ $f['severity'] }}]</span> {{ $f['title'] }}</h3>
      <div class="muted">{{ $f['rule_id'] }} · {{ $f['analyzer'] }} · confianza {{ $f['confidence'] }}{{ $f['cwe'] ? ' · '.$f['cwe'] : '' }}</div>
      @if ($f['location']['file'])
        <div class="mono">{{ $f['location']['file'] }}{{ $f['location']['line'] ? ':'.$f['location']['line'] : '' }}</div>
      @endif
      <p>{{ $f['description'] }}</p>
      @if ($f['remediation'])<div class="note"><strong>Corrección:</strong> {{ $f['remediation'] }}</div>@endif
      @foreach ($f['recommendations'] as $rec)
        @if ($rec['verify'])<div class="muted"><strong>Verificación:</strong> {{ $rec['verify'] }}</div>@endif
      @endforeach
    </div>
  @empty
    <p>No se registraron hallazgos.</p>
  @endforelse

  <h2>Integridad</h2>
  <p class="mono">findings_sha256 = {{ $integrity }}</p>
  <p class="muted">{{ $r['disclaimer'] }}</p>
</body>
</html>
