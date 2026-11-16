import { api } from '../api.js';
import { can, errorView, route } from '../app.js';
import { alertBox, badge, clear, field, fmtBytes, fmtDate, h, select, short, table, toast } from '../dom.js';

async function profiles() {
  const { data } = await api.get('/policies');
  return [...new Set(data.filter((p) => p.status === 'ACTIVE').map((p) => p.code))];
}

export async function renderProjects() {
  const { data } = await api.get('/projects?per_page=100');
  const list = h('div', { class: 'card flush' }, h('h2', {}, 'Proyectos'),
    table([
      { title: 'Nombre', render: (r) => h('strong', {}, r.name) },
      { title: 'Criticidad', render: (r) => h('span', { class: `badge sev-${r.criticality}` }, r.criticality) },
      { title: 'Perfil', key: 'default_profile' },
      { title: 'Última versión', render: (r) => r.latest_version?.version ?? '—' },
      { title: 'Último análisis', render: (r) => (r.latest_analysis ? badge(r.latest_analysis.status) : '—') },
      { title: 'Decisión', render: (r) => badge(r.latest_analysis?.decision) },
      { title: 'Responsable', key: 'owner' }],
    data, { onRow: (r) => { location.hash = `#/projects/${r.id}`; }, empty: 'No hay proyectos todavía.' }));

  let formCard = null;
  if (can('projects.create')) {
    const opts = await profiles();
    const msg = h('div');
    const form = h('form', { class: 'stack', onSubmit: async (ev) => {
      ev.preventDefault();
      clear(msg);
      const fd = new FormData(form);
      try {
        const res = await api.post('/projects', Object.fromEntries(fd));
        toast('Proyecto creado.');
        location.hash = `#/projects/${res.data.id}`;
      } catch (e) { msg.appendChild(errorView(e)); }
    } },
    field('Nombre', h('input', { name: 'name', required: true, minlength: 3, maxlength: 150 })),
    field('Descripción', h('input', { name: 'description', maxlength: 2000 })),
    h('div', { class: 'grid cols-2' },
      field('Criticidad', select('criticality', [['LOW', 'Baja'], ['MEDIUM', 'Media'], ['HIGH', 'Alta'], ['CRITICAL', 'Crítica']], 'MEDIUM')),
      field('Perfil de evaluación', select('default_profile', opts.map((o) => [o, o]), opts.includes('web-development') ? 'web-development' : opts[0]))),
    msg, h('div', {}, h('button', { class: 'btn primary', type: 'submit' }, 'Crear proyecto')));
    formCard = h('div', { class: 'card' }, h('h2', {}, 'Nuevo proyecto'), form);
  }

  return h('div', {},
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, 'Proyectos'), h('div', { class: 'sub' }, 'Proyectos web registrados y su último resultado.'))),
    h('div', { class: 'grid cols-3' }, h('div', { class: 'span-2' }, list), formCard));
}

export async function renderProject(id) {
  const { data: p } = await api.get(`/projects/${id}`);
  const opts = await profiles();

  // --- carga de versión
  let upload = null;
  if (can('versions.upload')) {
    const msg = h('div');
    const fileInput = h('input', { type: 'file', name: 'file', required: true, accept: '.zip,.php,.js,.ts,.tsx,.jsx,.html,.htm,.css,.json,.vue,.mjs,.cjs' });
    const btn = h('button', { class: 'btn primary', type: 'submit' }, 'Registrar versión');
    const form = h('form', { class: 'stack', onSubmit: async (ev) => {
      ev.preventDefault();
      clear(msg); btn.disabled = true;
      try {
        const res = await api.upload(`/projects/${id}/versions`, new FormData(form));
        msg.appendChild(alertBox('success', 'Artefacto registrado e inmutable. SHA-256: ', h('span', { class: 'hash' }, res.data.sha256)));
        toast('Versión registrada.');
        setTimeout(route, 900);
      } catch (e) { msg.appendChild(errorView(e)); btn.disabled = false; }
    } },
    field('Versión', h('input', { name: 'version', required: true, pattern: '[A-Za-z0-9._+\\-]{1,64}', placeholder: '1.4.0' }), 'Inmutable: una versión no puede reemplazarse.'),
    field('Artefacto (ZIP o fichero fuente)', fileInput, 'Se valida contra ZIP Slip, enlaces, bombas de compresión y nombres peligrosos.'),
    msg, h('div', {}, btn));
    upload = h('div', { class: 'card' }, h('h2', {}, 'Nueva versión'), form);
  }

  const versions = p.versions.map((v) => {
    const msg = h('div');
    const profileSel = select('profile', opts.map((o) => [o, o]), p.default_profile);
    const run = h('button', { class: 'btn primary small', onClick: async () => {
      clear(msg); run.disabled = true;
      try {
        const res = await api.post('/analyses', { project_version_id: v.id, profile: profileSel.value });
        location.hash = `#/analyses/${res.analysis_id}`;
      } catch (e) { msg.appendChild(errorView(e)); run.disabled = false; }
    } }, 'Analizar');
    const tech = v.technologies ?? {};
    return h('div', { class: 'card' },
      h('div', { class: 'row' }, h('h2', {}, `Versión ${v.version}`), h('span', { class: 'badge outline' }, v.artifact_kind),
        h('span', { class: 'muted small' }, `${fmtBytes(v.size_bytes)} · ${v.file_count} ficheros · ${fmtDate(v.created_at)}`)),
      h('dl', { class: 'kv' },
        h('dt', {}, 'SHA-256'), h('dd', { class: 'hash' }, v.sha256),
        h('dt', {}, 'Tecnologías'), h('dd', {}, [tech.primary_language, ...(tech.frameworks ?? [])].filter(Boolean).join(', ') || '—'),
        h('dt', {}, 'Lockfiles'), h('dd', {}, (tech.lockfiles ?? []).join(', ') || '—',
          (tech.manifests_without_lockfile ?? []).length ? h('div', { class: 'alert warn small' }, 'Manifiestos sin lockfile (SCA fallará en modo fail closed): ', tech.manifests_without_lockfile.join(', ')) : null)),
      can('analyses.create') ? h('div', { class: 'actions' }, profileSel, run) : null, msg,
      v.analyses.length ? table([
        { title: 'Análisis', render: (a) => h('a', { href: `#/analyses/${a.id}` }, short(a.id, 8)) },
        { title: 'Perfil', render: (a) => `${a.profile} v${a.policy_version ?? '?'}` },
        { title: 'Estado', render: (a) => badge(a.status) },
        { title: 'Decisión', render: (a) => badge(a.decision) },
        { title: 'Fecha', render: (a) => fmtDate(a.created_at) }], v.analyses) : h('p', { class: 'muted small' }, 'Sin análisis.'));
  });

  return h('div', {},
    h('div', { class: 'crumbs' }, h('a', { href: '#/projects' }, 'Proyectos'), ' / ', p.name),
    h('div', { class: 'page-head' }, h('div', {}, h('h1', {}, p.name),
      h('div', { class: 'sub' }, `Criticidad ${p.criticality} · perfil ${p.default_profile} · responsable ${p.owner}`, p.description ? ` · ${p.description}` : ''))),
    upload, versions.length ? versions : h('div', { class: 'card empty' }, 'Registre la primera versión para analizarla.'));
}
