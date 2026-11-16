import { api, qs } from '../api.js';
import { can, errorView, every, route } from '../app.js';
import { alertBox, badge, clear, field, fmtDate, h, label, select, sevBadge, short, table, toast } from '../dom.js';
import { severityBars } from './dashboard.js';

const FLOW = ['CREATED', 'VALIDATING', 'QUEUED', 'RUNNING', 'NORMALIZING', 'EVALUATING', 'COMPLETED'];
const ACTIVE = new Set(FLOW.slice(0, 6));

function pipeline(status) {
  const failed = ['FAILED', 'CANCELLED', 'TIMED_OUT', 'INCONCLUSIVE'].includes(status);
  const idx = FLOW.indexOf(status);
  return h('div', { class: 'pipeline', 'aria-label': 'Estado del análisis' },
    FLOW.map((s, i) => h('div', { class: `step ${i < idx || status === 'COMPLETED' ? 'done' : ''} ${i === idx ? 'current' : ''}` }, label(s))),
    failed ? h('div', { class: 'step failed' }, label(status)) : null);
}

function decisionPanel(a) {
  const d = a.decision;
  if (!d) {
    return h('div', { class: 'card' }, h('h2', {}, 'Decisión'),
      h('p', { class: 'muted' }, ACTIVE.has(a.status) ? 'La decisión se emitirá automáticamente cuando terminen todos los controles.' : 'Sin decisión emitida.'));
  }
  const reasons = d.reasons ?? [];
  return h('div', { class: 'card' }, h('h2', {}, 'Decisión firmada'),
    h('div', { class: `decision-hero ${d.result}` },
      h('div', {}, h('div', { class: 'result' }, label(d.result)),
        h('div', { class: 'meta' }, `Emitida ${fmtDate(d.issued_at)} · vence ${fmtDate(d.expires_at)} · clave ${d.key_id} · vía ${d.issued_via}`)),
      h('div', { style: null }, d.deployable ? h('strong', {}, 'Desplegable') : h('strong', {}, 'No desplegable'))),
    reasons.length
      ? h('ul', { class: 'reasons' }, reasons.map((r) => h('li', {}, badge(r.outcome), ' ', h('code', {}, r.code), ' — ', r.message)))
      : h('p', {}, 'Todos los controles obligatorios se cumplieron.'),
    h('dl', { class: 'kv small' }, h('dt', {}, 'Artefacto (SHA-256)'), h('dd', { class: 'hash' }, d.artifact_sha256),
      h('dt', {}, 'Política (SHA-256)'), h('dd', { class: 'hash' }, d.policy.sha256),
      h('dt', {}, 'Documento (SHA-256)'), h('dd', { class: 'hash' }, d.token_sha256)));
}

function findingsExplorer(a) {
  const results = h('div');
  const sev = select('severity', [['', 'Todas'], ...['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => [s, label(s)])], '');
  const cat = select('category', [['', 'Todas'], ['sast', 'SAST'], ['sca', 'SCA'], ['secrets', 'Secretos'], ['quality', 'Calidad'], ['dast', 'DAST']], '');
  const analyzers = [...new Set(a.jobs.map((j) => j.analyzer))];
  const an = select('analyzer', [['', 'Todos'], ...analyzers.map((x) => [x, x])], '');
  const q = h('input', { name: 'q', placeholder: 'Regla, fichero o título' });
  let page = 1;
  const load = async () => {
    clear(results).appendChild(h('div', { class: 'boot' }, 'Cargando hallazgos…'));
    try {
      const res = await api.get(`/analyses/${a.id}/findings${qs({ severity: sev.value, category: cat.value, analyzer: an.value, q: q.value, page, per_page: 50 })}`);
      const pages = Math.max(1, Math.ceil(res.meta.total / res.meta.per_page));
      clear(results).append(
        table([
          { title: 'Severidad', render: (f) => sevBadge(f.severity) },
          { title: 'Hallazgo', render: (f) => h('div', {}, h('strong', {}, f.title), h('div', { class: 'muted small mono' }, f.rule_id)) },
          { title: 'Ubicación', render: (f) => h('span', { class: 'mono small' }, f.location.file ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}` : '—') },
          { title: 'Confianza', render: (f) => label(f.confidence) },
          { title: 'Origen', render: (f) => h('span', { class: 'small' }, `${f.analyzer} · ${f.cwe ?? f.category}`) },
          { title: '', render: (f) => (f.pending_exceptions ? badge('PENDING') : '') }],
        res.data, { onRow: (f) => { location.hash = `#/findings/${f.id}`; }, empty: 'Sin hallazgos con estos filtros.' }),
        h('div', { class: 'row small muted' }, `${res.meta.total} hallazgos · página ${res.meta.page} de ${pages}`,
          h('button', { class: 'btn small', disabled: page <= 1 ? true : null, onClick: () => { page--; load(); } }, '‹ Anterior'),
          h('button', { class: 'btn small', disabled: page >= pages ? true : null, onClick: () => { page++; load(); } }, 'Siguiente ›')));
    } catch (e) { clear(results).appendChild(errorView(e)); }
  };
  [sev, cat, an].forEach((el) => el.addEventListener('change', () => { page = 1; load(); }));
  q.addEventListener('keydown', (e) => { if (e.key === 'Enter') { page = 1; load(); } });
  load();
  return h('div', { class: 'card' }, h('h2', {}, 'Hallazgos'),
    h('div', { class: 'filters' }, field('Severidad', sev), field('Categoría', cat), field('Analizador', an), field('Buscar', q)), results);
}

async function compareCard(a) {
  const { data: project } = await api.get(`/projects/${a.project_version.project_id}`);
  const others = project.versions.flatMap((v) => v.analyses.map((x) => ({ ...x, version: v.version }))).filter((x) => x.id !== a.id);
  if (!others.length) return null;
  const out = h('div');
  const sel = select('base', others.map((o) => [o.id, `v${o.version} · ${short(o.id, 8)} · ${label(o.status)}`]), others[0].id);
  const btn = h('button', { class: 'btn small', onClick: async () => {
    clear(out);
    try {
      const { data } = await api.get(`/analyses/${a.id}/compare/${sel.value}`);
      const cols = [{ title: 'Severidad', render: (f) => sevBadge(f.severity) }, { title: 'Hallazgo', key: 'title' },
        { title: 'Ubicación', render: (f) => h('span', { class: 'mono small' }, `${f.location.file ?? ''}:${f.location.line ?? ''}`) }];
      out.append(
        h('p', {}, h('strong', {}, `${data.counts.new} nuevos`), ` · ${data.counts.fixed} corregidos · ${data.counts.persisting} persistentes (respecto a v${data.base.version})`),
        h('h3', {}, 'Nuevos'), table(cols, data.new, { empty: 'Ninguno.' }),
        h('h3', {}, 'Corregidos'), table(cols, data.fixed, { empty: 'Ninguno.' }));
    } catch (e) { out.appendChild(errorView(e)); }
  } }, 'Comparar');
  return h('div', { class: 'card' }, h('h2', {}, 'Comparar con otra versión'), h('div', { class: 'actions' }, sel, btn), out);
}

export async function renderAnalysis(id) {
  const { data: a } = await api.get(`/analyses/${id}`);
  const msg = h('div');
  const act = (text, fn, cls = 'btn') => h('button', { class: cls, onClick: async (ev) => {
    ev.target.disabled = true; clear(msg);
    try { await fn(); } catch (e) { msg.appendChild(errorView(e)); } finally { ev.target.disabled = false; }
  } }, text);

  const actions = h('div', { class: 'actions' },
    a.decision ? act('Descargar autorización (.jws)', () => api.download(`/analyses/${id}/decision/token`, `vulnix-authorization-${id}.jws`)) : null,
    ...['pdf', 'html', 'sarif', 'json'].map((f) => act(f.toUpperCase(), async () => {
      const sha = await api.download(`/analyses/${id}/report?format=${f}`, `vulnix-${id}.${f === 'sarif' ? 'sarif' : f}`);
      toast(`Reporte ${f.toUpperCase()} descargado · SHA-256 ${short(sha, 16)}`);
    }, 'btn small')),
    can('analyses.evaluate') && !ACTIVE.has(a.status) ? act('Reevaluar', async () => { await api.post(`/analyses/${id}/evaluate`); toast('Nueva decisión emitida.'); route(); }) : null,
    can('analyses.create') && ['CREATED', 'VALIDATING', 'QUEUED', 'RUNNING'].includes(a.status)
      ? act('Cancelar', async () => { await api.post(`/analyses/${id}/cancel`); route(); }, 'btn danger') : null);

  if (ACTIVE.has(a.status)) {
    every(3000, async () => {
      try {
        const { data } = await api.get(`/analyses/${id}`);
        if (data.status !== a.status || JSON.stringify(data.jobs.map((j) => j.status)) !== JSON.stringify(a.jobs.map((j) => j.status))) route();
      } catch { /* se reintenta en el siguiente ciclo */ }
    });
  }

  const jobs = table([
    { title: 'Analizador', render: (j) => h('div', {}, h('strong', {}, j.analyzer), j.mandatory ? '' : h('span', { class: 'muted small' }, ' (opcional)')) },
    { title: 'Categoría', key: 'category' },
    { title: 'Versión', render: (j) => h('span', { class: 'mono small' }, j.analyzer_version ?? '—') },
    { title: 'Intento', key: 'attempt', class: 'right' },
    { title: 'Estado', render: (j) => badge(j.status) },
    { title: 'Detalle', render: (j) => (j.error_type ? h('div', { class: 'small' }, h('code', {}, j.error_type), h('div', { class: 'muted' }, (j.error_message ?? '').slice(0, 220))) :
      h('span', { class: 'muted small' }, j.metadata?.findings != null ? `${j.metadata.findings} hallazgos · ${j.metadata.duration_s ?? '?'} s · ${j.metadata.isolation_level ?? ''}` : '')) }],
  a.jobs);

  const checks = a.decision ? (await api.get(`/analyses/${id}/decision`)).data.checks : [];
  return h('div', {},
    h('div', { class: 'crumbs' }, h('a', { href: '#/projects' }, 'Proyectos'), ' / ',
      h('a', { href: `#/projects/${a.project_version.project_id}` }, a.project_version.project_name), ' / ', `v${a.project_version.version}`),
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, `Análisis ${short(a.id, 8)}`),
      h('div', { class: 'sub' }, `Perfil ${a.profile} v${a.policy?.version} · solicitado por ${a.requested_by} · ${fmtDate(a.created_at)}`)), actions),
    msg,
    h('div', { class: 'card' }, pipeline(a.status), a.status_reason ? alertBox('warn', a.status_reason) : null,
      h('dl', { class: 'kv small' }, h('dt', {}, 'Artefacto (SHA-256)'), h('dd', { class: 'hash' }, a.artifact_sha256))),
    h('div', { class: 'grid cols-2' }, decisionPanel(a),
      h('div', { class: 'card' }, h('h2', {}, 'Resumen de hallazgos'), severityBars(a.findings_by_severity),
        checks.length ? h('div', {}, h('h3', {}, 'Controles'), h('div', { class: 'actions' }, checks.map((c) => h('span', { class: `badge ${c.status}` }, `${c.control}: ${label(c.status)}`)))) : null)),
    h('div', { class: 'card flush' }, h('h2', {}, 'Controles ejecutados'), jobs),
    findingsExplorer(a),
    await compareCard(a));
}

export async function renderAnalyses() {
  const { data } = await api.get('/analyses?per_page=100');
  return h('div', {},
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Análisis'), h('div', { class: 'sub' }, 'Historial de evaluaciones y decisiones.'))),
    h('div', { class: 'card flush' }, table([
      { title: 'Análisis', render: (r) => h('span', { class: 'mono' }, short(r.id, 8)) },
      { title: 'Proyecto', render: (r) => r.project_version?.project_name },
      { title: 'Versión', render: (r) => r.project_version?.version },
      { title: 'Perfil', key: 'profile' },
      { title: 'Estado', render: (r) => badge(r.status) },
      { title: 'Decisión', render: (r) => badge(r.decision) },
      { title: 'Fecha', render: (r) => fmtDate(r.created_at) }], data, { onRow: (r) => { location.hash = `#/analyses/${r.id}`; }, empty: 'Sin análisis.' })));
}
