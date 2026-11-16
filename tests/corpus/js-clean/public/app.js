const params = new URLSearchParams(location.search);
const q = params.get('q');
document.getElementById('results').textContent = 'Resultados para ' + q;
const el = document.createElement('p');
el.innerHTML = '<strong>Bienvenido</strong>';
const token = crypto.randomUUID();
window.parent.postMessage({ ok: true }, 'https://app.example.com');
window.location.href = '/login';
