import { api } from '../api.js';
import { badge, fmtDate, h, label, table } from '../dom.js';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export function severityBars(counts) {
  const max = Math.max(1, ...SEVERITIES.map((s) => Number(counts?.[s] ?? 0)));
  return h('div', { class: 'bars' }, SEVERITIES.map((s) => {
    const n = Number(counts?.[s] ?? 0);
    const fill = h('div', { class: `fill sev-${s}` });
    fill.style.width = `${(n / max) * 100}%`; // CSSOM: permitido por la CSP
    return h('div', { class: 'bar' }, h('span', {}, label(s)), h('div', { class: 'track' }, fill), h('span', { class: 'n' }, n));
  }));
}

export async function renderDashboard() {
  const { data } = await api.get('/dashboard');
  const d = data.decisions_by_result ?? {};
  const running = ['CREATED', 'VALIDATING', 'QUEUED', 'RUNNING', 'NORMALIZING', 'EVALUATING']
    .reduce((acc, s) => acc + Number(data.analyses_by_status?.[s] ?? 0), 0);
  const kpi = (lbl, value, cls = '') => h('div', { class: `kpi ${cls}` }, h('div', { class: 'label' }, lbl), h('div', { class: 'value' }, value ?? 0));

  return h('div', {},
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Panel'), h('div', { class: 'sub' }, 'Estado del gate de despliegue y de los análisis recientes.')),
      h('div', { class: 'actions' }, h('a', { class: 'btn primary', href: '#/projects' }, 'Analizar un proyecto'))),
    h('div', { class: 'kpis' },
      kpi('Proyectos', data.projects),
      kpi('En curso', running),
      kpi('Aprobados', d.APPROVED, 'ok'),
      kpi('Rechazados', d.REJECTED, 'bad'),
      kpi('Revisión requerida', d.REVIEW_REQUIRED, 'warn'),
      kpi('Inconclusos', d.INCONCLUSIVE, 'neutral')),
    h('div', { class: 'grid cols-2' },
      h('div', { class: 'card' }, h('h2', {}, 'Hallazgos (últimos 30 días)'), severityBars(data.findings_last_30d_by_severity)),
      h('div', { class: 'card' }, h('h2', {}, 'Inteligencia de vulnerabilidades'),
        data.intel?.length
          ? table([
            { title: 'Ecosistema', key: 'ecosystem' },
            { title: 'Datos a', render: (r) => fmtDate(r.imported_at) },
            { title: 'Antigüedad', render: (r) => h('span', { class: r.age_days > 7 ? 'badge FAILED' : 'badge PASS' }, `${r.age_days} días`) },
            { title: 'Avisos', key: 'records', class: 'right' }], data.intel)
          : h('div', { class: 'alert warn' }, 'No hay inteligencia OSV importada: los análisis SCA con dependencias serán INCONCLUSOS (fail closed). Ejecute vulnix-intel import.'))),
    h('div', { class: 'card flush' }, h('h2', {}, 'Análisis recientes'),
      table([
        { title: 'Proyecto', render: (r) => r.project_version?.project_name },
        { title: 'Versión', render: (r) => r.project_version?.version },
        { title: 'Perfil', key: 'profile' },
        { title: 'Estado', render: (r) => badge(r.status) },
        { title: 'Decisión', render: (r) => badge(r.decision) },
        { title: 'Fecha', render: (r) => fmtDate(r.created_at), class: 'nowrap' }],
      data.recent_analyses ?? [], { onRow: (r) => { location.hash = `#/analyses/${r.id}`; }, empty: 'Todavía no hay análisis.' })));
}

export async function renderSystem() {
  const { data } = await api.get('/system/health');
  const ok = (v) => badge(v ? 'PASS' : 'FAIL');
  return h('div', {},
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Sistema'), h('div', { class: 'sub' }, 'Salud de componentes, colas y analizadores.'))),
    h('div', { class: 'card' }, h('dl', { class: 'kv' },
      h('dt', {}, 'Base de datos'), h('dd', {}, ok(data.database)),
      h('dt', {}, 'Clave de firma'), h('dd', {}, ok(data.signing_key?.present), ' ', h('span', { class: 'hash' }, data.signing_key?.key_id ?? '')),
      h('dt', {}, 'Almacenamiento'), h('dd', {}, ok(data.storage?.writable), ' ', h('span', { class: 'muted small' }, data.storage?.free_bytes ? `${(data.storage.free_bytes / 1e9).toFixed(1)} GB libres` : '')),
      h('dt', {}, 'Orquestador'), h('dd', {}, ok(data.orchestrator?.alive), h('span', { class: 'muted small' }, ' latido < 3 min')),
      h('dt', {}, 'API de analizadores'), h('dd', {}, ok(data.analyzer_api?.reachable)),
      h('dt', {}, 'Cola'), h('dd', {}, `${data.queue?.QUEUED ?? 0} en cola · ${data.queue?.RUNNING ?? 0} en ejecución`))),
    h('div', { class: 'card flush' }, h('h2', {}, 'Analizadores registrados'),
      table([
        { title: 'Nombre', key: 'name' }, { title: 'Categoría', key: 'category' },
        { title: 'Versión', render: (r) => h('span', { class: 'mono' }, r.version) },
        { title: 'Estado', render: (r) => ok(r.healthy) }, { title: 'Detalle', key: 'detail' },
        { title: 'Último latido', render: (r) => fmtDate(r.last_seen_at) }], data.analyzers ?? [],
      { empty: 'El orquestador aún no ha registrado analizadores.' })));
}
