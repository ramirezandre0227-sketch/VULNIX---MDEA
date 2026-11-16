const params = new URLSearchParams(location.search);
const q = params.get('q');
document.getElementById('results').innerHTML = 'Resultados para ' + q;
const frag = location.hash.substring(1);
document.write(frag);
const sessionToken = Math.random().toString(36).slice(2);
window.parent.postMessage({ token: sessionToken }, '*');
const githubToken = 'ghp_1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX3';
