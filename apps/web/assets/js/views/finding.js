import { api } from '../api.js';
import { can, errorView, route } from '../app.js';
import { badge, clear, externalLink, field, fmtBytes, fmtDate, h, label, select, sevBadge, toast } from '../dom.js';

export async function renderFinding(id) {
  const { data: f } = await api.get(`/findings/${id}`);

  let requestForm = null;
  const hasPending = f.exceptions.some((e) => e.status === 'PENDING');
  if (can('exceptions.request') && !hasPending) {
    const msg = h('div');
    const max = new Date(Date.now() + 90 * 864e5).toISOString().slice(0, 10);
    const def = new Date(Date.now() + 30 * 864e5).toISOString().slice(0, 10);
    const form = h('form', { class: 'stack', onSubmit: async (ev) => {
      ev.preventDefault(); clear(msg);
      const fd = Object.fromEntries(new FormData(form));
      try {
        await api.post('/exceptions', { finding_id: id, kind: fd.kind, reason: fd.reason, expires_at: `${fd.expires_at}T23:59:59Z` });
        toast('Excepción solicitada: queda pendiente de un aprobador.');
        route();
      } catch (e) { msg.appendChild(errorView(e)); }
    } },
    h('div', { class: 'grid cols-2' },
      field('Tipo', select('kind', [['FALSE_POSITIVE', 'Falso positivo'], ['ACCEPTED_RISK', 'Riesgo aceptado']], 'FALSE_POSITIVE')),
      field('Vence', h('input', { type: 'date', name: 'expires_at', required: true, value: def, max }), 'Obligatorio; máximo 90 días.')),
    field('Justificación', h('textarea', { name: 'reason', required: true, minlength: 20, maxlength: 4000, class: 'short' }), 'Mínimo 20 caracteres. Quedará auditada.'),
    msg, h('div', {}, h('button', { class: 'btn primary', type: 'submit' }, 'Solicitar excepción')));
    requestForm = h('div', { class: 'card' }, h('h2', {}, 'Solicitar excepción'),
      h('p', { class: 'muted small' }, 'Una excepción no modifica el hallazgo original: es una resolución separada que requiere aprobación de otra persona y vence automáticamente.'), form);
  }

  const rec = f.recommendations[0];
  return h('div', {},
    h('div', { class: 'crumbs' }, h('a', { href: `#/projects/${f.project.id}` }, f.project.name), ' / ', h('a', { href: `#/analyses/${f.analysis_id}` }, 'Análisis'), ' / Hallazgo'),
    h('div', { class: 'page-head' }, h('div', {}, h('div', { class: 'row' }, sevBadge(f.severity), h('span', { class: 'badge outline' }, `Confianza ${label(f.confidence)}`),
      f.cwe ? externalLink(`https://cwe.mitre.org/data/definitions/${f.cwe.split('-')[1]}.html`, f.cwe) : null),
    h('h1', {}, f.title), h('div', { class: 'sub mono' }, f.rule_id))),
    h('div', { class: 'grid cols-2' },
      h('div', { class: 'card' }, h('h2', {}, 'Descripción'), h('p', {}, f.description),
        h('dl', { class: 'kv' },
          h('dt', {}, 'Ubicación'), h('dd', { class: 'mono' }, f.location.file ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ''}` : '—'),
          h('dt', {}, 'Analizador'), h('dd', {}, `${f.analyzer} ${f.analyzer_version ?? ''} · ${f.category}`),
          h('dt', {}, 'Huella'), h('dd', { class: 'hash' }, f.fingerprint)),
        f.snippet ? h('div', {}, h('h3', {}, 'Evidencia (redactada)'), h('pre', { class: 'snippet' }, f.snippet)) : null),
      h('div', { class: 'card' }, h('h2', {}, 'Corrección propuesta'),
        h('p', {}, f.remediation ?? rec?.description ?? 'Sin recomendación específica.'),
        rec?.verify ? h('div', {}, h('h3', {}, 'Cómo verificar'), h('p', {}, rec.verify)) : null,
        (rec?.references ?? []).length ? h('div', {}, h('h3', {}, 'Referencias'), h('ul', {}, rec.references.map((u) => h('li', {}, externalLink(u))))) : null,
        h('p', { class: 'muted small' }, 'Las correcciones deben revisarse y probarse antes de desplegarse (manual §1: sin parches automáticos).'))),
    h('div', { class: 'card' }, h('h2', {}, 'Evidencias'),
      [...f.evidences, ...f.job_evidences].length ? h('ul', {}, [...f.evidences, ...f.job_evidences].map((e) => h('li', {},
        h('code', {}, e.kind), ` · ${fmtBytes(e.size_bytes)} · `, h('span', { class: 'hash' }, e.sha256), ' ',
        h('button', { class: 'btn small', onClick: async () => {
          try { await api.download(`/evidences/${e.id}/download`, `evidence-${e.id}.json`); } catch (err) { toast(err.message, 'error'); }
        } }, 'Descargar')))) : h('p', { class: 'muted' }, 'Sin evidencias asociadas.')),
    h('div', { class: 'card' }, h('h2', {}, 'Excepciones'),
      f.exceptions.length ? h('ul', {}, f.exceptions.map((e) => h('li', {}, badge(e.status), ` ${label(e.kind)} · solicitada por ${e.requested_by} · vence ${fmtDate(e.expires_at)}`,
        e.approver ? ` · decidida por ${e.approver}` : '', h('div', { class: 'muted small' }, e.reason)))) : h('p', { class: 'muted' }, 'Sin excepciones.')),
    requestForm);
}
