import { api, qs } from '../api.js';
import { can, errorView, route, state } from '../app.js';
import { alertBox, badge, clear, field, fmtDate, h, label, select, sevBadge, short, table, toast } from '../dom.js';

export async function renderExceptions() {
  const status = new URLSearchParams(location.hash.split('?')[1] ?? '').get('status') ?? 'PENDING';
  const { data } = await api.get(`/exceptions${qs({ status })}`);
  const sel = select('status', [['PENDING', 'Pendientes'], ['APPROVED', 'Aprobadas'], ['REJECTED', 'Rechazadas'], ['REVOKED', 'Revocadas'], ['', 'Todas']], status);
  sel.addEventListener('change', () => { location.hash = `#/exceptions?status=${sel.value}`; });

  const decide = (e, decision) => async () => {
    const note = window.prompt(`${decision === 'APPROVE' ? 'Aprobar' : decision === 'REJECT' ? 'Rechazar' : 'Revocar'}: nota obligatoria (mín. 5 caracteres)`);
    if (!note) return;
    try {
      await api.post(`/exceptions/${e.id}/decision`, { decision, note });
      toast('Decisión registrada.');
      route();
    } catch (err) { toast(`${err.code}: ${err.message}`, 'error'); }
  };

  return h('div', {},
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Excepciones'),
      h('div', { class: 'sub' }, 'Resoluciones auditables con aprobador distinto del solicitante y vencimiento obligatorio.')),
    h('div', { class: 'filters' }, field('Estado', sel))),
    h('div', { class: 'card flush' }, table([
      { title: 'Estado', render: (e) => h('div', {}, badge(e.status), e.status === 'APPROVED' && !e.effective ? h('div', { class: 'small muted' }, 'vencida') : null) },
      { title: 'Hallazgo', render: (e) => h('div', {}, sevBadge(e.finding.severity), ' ', h('a', { href: `#/findings/${e.finding_id}` }, e.finding.title),
        h('div', { class: 'small mono muted' }, `${e.finding.file ?? ''}:${e.finding.line ?? ''}`)) },
      { title: 'Proyecto', key: 'project' },
      { title: 'Tipo', render: (e) => label(e.kind) },
      { title: 'Justificación', render: (e) => h('div', { class: 'small' }, e.reason) },
      { title: 'Solicitante', key: 'requested_by' },
      { title: 'Vence', render: (e) => fmtDate(e.expires_at) },
      { title: '', render: (e) => (e.can_decide ? h('div', { class: 'actions' },
        e.status === 'PENDING' ? h('button', { class: 'btn small primary', onClick: decide(e, 'APPROVE') }, 'Aprobar') : null,
        e.status === 'PENDING' ? h('button', { class: 'btn small danger', onClick: decide(e, 'REJECT') }, 'Rechazar') : null,
        e.status === 'APPROVED' ? h('button', { class: 'btn small danger', onClick: decide(e, 'REVOKE') }, 'Revocar') : null) : '') }],
    data, { empty: 'No hay excepciones en este estado.' })));
}

export async function renderPolicies() {
  const { data } = await api.get('/policies');
  let createCard = null;
  if (can('policies.create')) {
    const msg = h('div');
    const ta = h('textarea', { name: 'yaml', required: true, spellcheck: 'false' });
    const active = data.find((p) => p.status === 'ACTIVE');
    if (active) {
      const { data: full } = await api.get(`/policies/${active.id}`);
      ta.value = (full.source_yaml ?? '').replace(/^version:.*$/m, 'version: "X.Y"');
    }
    createCard = h('div', { class: 'card' }, h('h2', {}, 'Nueva versión de política'),
      h('p', { class: 'muted small' }, 'Las políticas son inmutables y se crean en borrador. Un aprobador distinto del autor debe activarlas. fail_closed: true es obligatorio.'),
      h('form', { class: 'stack', onSubmit: async (ev) => {
        ev.preventDefault(); clear(msg);
        try {
          const res = await api.post('/policies', { yaml: ta.value });
          toast(`Política ${res.data.code} v${res.data.version} creada en borrador.`);
          location.hash = `#/policies/${res.data.id}`;
        } catch (e) { msg.appendChild(errorView(e)); }
      } }, ta, msg, h('div', {}, h('button', { class: 'btn primary', type: 'submit' }, 'Crear borrador'))));
  }
  return h('div', {},
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Políticas'), h('div', { class: 'sub' }, 'Reglas versionadas que gobiernan la decisión del gate.'))),
    h('div', { class: 'card flush' }, table([
      { title: 'Código', render: (p) => h('strong', {}, p.code) }, { title: 'Versión', key: 'version' },
      { title: 'Estado', render: (p) => badge(p.status) },
      { title: 'Controles obligatorios', render: (p) => (p.rules.required ?? []).join(', ') },
      { title: 'SHA-256', render: (p) => h('span', { class: 'hash' }, short(p.sha256, 16)) },
      { title: 'Aprobada', render: (p) => (p.approved_at ? `${fmtDate(p.approved_at)} · ${p.approved_by ?? 'sistema'}` : '—') }],
    data, { onRow: (p) => { location.hash = `#/policies/${p.id}`; } })),
    createCard);
}

export async function renderPolicy(id) {
  const { data: p } = await api.get(`/policies/${id}`);
  const msg = h('div');
  const canApprove = can('policies.approve') && p.status === 'DRAFT' && p.created_by !== state.user.username;
  return h('div', {},
    h('div', { class: 'crumbs' }, h('a', { href: '#/policies' }, 'Políticas'), ' / ', p.code),
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, `${p.code} v${p.version}`), h('div', { class: 'sub' }, p.rules.description ?? '')),
      canApprove ? h('button', { class: 'btn primary', onClick: async () => {
        clear(msg);
        try { await api.post(`/policies/${id}/approve`); toast('Política aprobada y activada.'); route(); } catch (e) { msg.appendChild(errorView(e)); }
      } }, 'Aprobar y activar') : null),
    msg,
    p.status === 'DRAFT' && can('policies.approve') && !canApprove ? alertBox('warn', 'Segregación de funciones: no puede aprobar una política creada por usted.') : null,
    h('div', { class: 'card' }, h('dl', { class: 'kv' },
      h('dt', {}, 'Estado'), h('dd', {}, badge(p.status)),
      h('dt', {}, 'SHA-256'), h('dd', { class: 'hash' }, p.sha256),
      h('dt', {}, 'Creada por'), h('dd', {}, p.created_by ?? 'sistema (sincronización)'),
      h('dt', {}, 'Aprobada por'), h('dd', {}, p.approved_by ?? (p.approved_at ? 'sistema (entorno local)' : '—')))),
    h('div', { class: 'card' }, h('h2', {}, 'Fuente YAML'), h('pre', { class: 'snippet' }, p.source_yaml ?? JSON.stringify(p.rules, null, 2))));
}
