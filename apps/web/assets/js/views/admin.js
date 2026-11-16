import { api, qs } from '../api.js';
import { can, errorView, route, state } from '../app.js';
import { alertBox, badge, clear, field, fmtDate, h, select, short, table, toast } from '../dom.js';

export async function renderAudit() {
  const params = new URLSearchParams(location.hash.split('?')[1] ?? '');
  const filters = { action: params.get('action') ?? '', actor: params.get('actor') ?? '', entity_id: params.get('entity_id') ?? '' };
  const { data, meta } = await api.get(`/audit-logs${qs({ ...filters, per_page: 100 })}`);
  const verifyOut = h('div');
  const inputs = Object.fromEntries(Object.entries(filters).map(([k, v]) => [k, h('input', { name: k, value: v })]));
  const apply = () => { location.hash = `#/audit${qs(Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, i.value])))}`; };
  Object.values(inputs).forEach((i) => i.addEventListener('keydown', (e) => { if (e.key === 'Enter') apply(); }));

  return h('div', {},
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Auditoría'),
      h('div', { class: 'sub' }, `Registro append-only encadenado por hash · ${meta.total} entradas`)),
    h('button', { class: 'btn', onClick: async () => {
      clear(verifyOut);
      try {
        const { data: r } = await api.get('/audit-logs/verify');
        verifyOut.appendChild(r.valid ? alertBox('success', `Cadena íntegra: ${r.entries} entradas verificadas.`)
          : alertBox('error', `Cadena ROTA en: ${JSON.stringify(r.broken)}`));
      } catch (e) { verifyOut.appendChild(errorView(e)); }
    } }, 'Verificar integridad')),
    verifyOut,
    h('div', { class: 'filters' }, field('Acción (prefijo)', inputs.action), field('Usuario', inputs.actor), field('Entidad (id)', inputs.entity_id),
      h('button', { class: 'btn', onClick: apply }, 'Filtrar')),
    h('div', { class: 'card flush' }, table([
      { title: '#', key: 'seq', class: 'right' },
      { title: 'Fecha', render: (l) => h('span', { class: 'nowrap' }, fmtDate(l.created_at)) },
      { title: 'Actor', render: (l) => l.actor ?? h('span', { class: 'muted' }, l.actor_type) },
      { title: 'Acción', render: (l) => h('code', {}, l.action) },
      { title: 'Entidad', render: (l) => (l.entity_type ? h('span', { class: 'small' }, `${l.entity_type} `, h('span', { class: 'hash' }, short(l.entity_id, 8))) : '—') },
      { title: 'Evento', render: (l) => h('pre', { class: 'snippet small' }, JSON.stringify(l.event)) },
      { title: 'Hash', render: (l) => h('span', { class: 'hash' }, short(l.hash, 10)) }], data)));
}

export async function renderUsers() {
  const { data } = await api.get('/users');
  const roles = [['developer', 'Desarrollador'], ['security_reviewer', 'Revisor de seguridad'], ['approver', 'Aprobador'], ['admin', 'Administrador'], ['auditor', 'Auditor']];
  if (can('users.manage_superadmin')) roles.push(['superadmin', 'Superadministrador']);
  const msg = h('div');
  const form = h('form', { class: 'stack', onSubmit: async (ev) => {
    ev.preventDefault(); clear(msg);
    try {
      await api.post('/users', Object.fromEntries(new FormData(form)));
      toast('Usuario creado.');
      route();
    } catch (e) { msg.appendChild(errorView(e)); }
  } },
  h('div', { class: 'grid cols-2' },
    field('Usuario', h('input', { name: 'username', required: true, minlength: 3, maxlength: 64 }), 'Se guarda en minúsculas; admite espacios internos.'),
    field('Nombre', h('input', { name: 'display_name', required: true }))),
  h('div', { class: 'grid cols-2' },
    field('Correo', h('input', { name: 'email', type: 'email' })),
    field('Rol', select('role', roles, 'developer'))),
  field('Contraseña inicial', h('input', { name: 'password', type: 'password', required: true, minlength: 12, autocomplete: 'new-password' }),
    'Mínimo 12 caracteres con mayúsculas, minúsculas y números.'),
  msg, h('div', {}, h('button', { class: 'btn primary', type: 'submit' }, 'Crear usuario')));

  const toggle = (u) => async () => {
    try { await api.patch(`/users/${u.id}`, { active: !u.active }); toast('Usuario actualizado.'); route(); } catch (e) { toast(e.message, 'error'); }
  };
  return h('div', {},
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Usuarios'), h('div', { class: 'sub' }, 'Roles separados: desarrollador, revisor, aprobador, administrador y auditor.'))),
    h('div', { class: 'card flush' }, table([
      { title: 'Usuario', render: (u) => h('div', {}, h('strong', {}, u.username), h('div', { class: 'small muted' }, u.display_name)) },
      { title: 'Rol', key: 'role_label' },
      { title: 'Estado', render: (u) => badge(u.active ? 'ACTIVE' : 'REVOKED') },
      { title: 'Último acceso', render: (u) => fmtDate(u.last_login_at) },
      { title: '', render: (u) => (u.id === state.user.id || (u.role === 'superadmin' && !can('users.manage_superadmin')) ? ''
        : h('button', { class: 'btn small', onClick: toggle(u) }, u.active ? 'Desactivar' : 'Activar')) }], data)),
    h('div', { class: 'card' }, h('h2', {}, 'Nuevo usuario'), form));
}
