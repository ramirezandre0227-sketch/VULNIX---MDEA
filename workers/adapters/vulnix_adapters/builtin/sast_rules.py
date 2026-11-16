"""Reglas SAST integradas (PHP, JavaScript/TypeScript, HTML, CSS).

Motor de patrones por línea con rastreo de contaminación (taint) intra-fichero:
- `sources`: expresiones de entrada no confiable (superglobales, req.query, location.hash...).
- Una variable asignada desde una fuente sin sanitizador queda contaminada en el resto del fichero.
- Reglas `taint: "required"` solo disparan si la línea usa una fuente o variable contaminada;
  reglas `taint: "upgrade"` elevan la confianza a HIGH en ese caso.

Es un analizador heurístico: complementa (no sustituye) a herramientas semánticas como Semgrep.
La confianza declarada refleja esa limitación y el motor de políticas envía a revisión humana
los hallazgos críticos/altos que no tengan confianza alta.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

OWASP_A03 = "https://owasp.org/Top10/A03_2021-Injection/"
OWASP_A02 = "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
OWASP_A05 = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
OWASP_A08 = "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
OWASP_A01 = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
OWASP_A10 = "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"


def cwe_url(cwe: str) -> str:
    return f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"


@dataclass(frozen=True)
class Rule:
    id: str
    languages: frozenset[str]
    pattern: re.Pattern[str]
    severity: str
    confidence: str
    cwe: str
    title: str
    description: str
    remediation: str
    verify: str
    references: tuple[str, ...] = ()
    exclude: re.Pattern[str] | None = None
    taint: str | None = None                    # None | "required" | "upgrade"
    file_requires: re.Pattern[str] | None = None
    path_filter: re.Pattern[str] | None = None
    extra: dict = field(default_factory=dict)


def R(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


PHP, JS, HTML, CSS = frozenset({"php"}), frozenset({"js"}), frozenset({"html", "php", "js"}), frozenset({"css"})

# ----------------------------------------------------------------------------- fuentes y sanitizadores
PHP_SOURCE = R(r"\$_(GET|POST|REQUEST|COOKIE|FILES)\b|\$_SERVER\s*\[\s*['\"](PHP_SELF|REQUEST_URI|QUERY_STRING|HTTP_[A-Z_]+)['\"]|php://input|\$request->(input|query|get|post|all)\s*\(|request\s*\(\s*\)\s*->\s*(input|query|get|all)\s*\(|Request::(input|query|get|all)\s*\(")
PHP_ASSIGN = R(r"(\$[A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*=(?!=)\s*(.+)")
PHP_SANITIZERS = R(r"(?:\b(intval|floatval|boolval|filter_var|filter_input|htmlspecialchars|htmlentities|strip_tags|ctype_\w+|is_numeric|preg_replace|basename|escapeshellarg|escapeshellcmd|mysqli_real_escape_string|real_escape_string|json_encode|urlencode|rawurlencode|e)\s*\(|->quote\s*\(|PDO::quote|\(\s*(int|integer|float|double|bool|boolean)\s*\))", re.I)

JS_SOURCE = R(r"\breq\.(query|params|body|cookies|headers)\b|\brequest\.(query|params|body)\b|\blocation\.(hash|search|href|pathname)\b|\bdocument\.(URL|documentURI|referrer|cookie)\b|\bwindow\.name\b|\bURLSearchParams\b|\.searchParams\.get\s*\(|\bevent\.data\b|\be\.data\b|\bmessage\.data\b")
JS_ASSIGN = R(r"(?:\b(?:const|let|var)\s+|^\s*)([A-Za-z_$][\w$]*)\s*=(?!=)\s*(.+)")
JS_DESTRUCT = R(r"\b(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(.+)")
JS_SANITIZERS = R(r"\b(DOMPurify\.sanitize|sanitizeHtml|escapeHtml|encodeURIComponent|encodeURI|parseInt|parseFloat|Number|validator\.\w+|xss\s*\(|textContent)\b")

# ----------------------------------------------------------------------------- reglas
RULES: list[Rule] = [
    # ======================================================================= PHP
    Rule("php.sql-injection", PHP,
         R(r"(?i)\b(mysqli_query|mysql_query|mysqli_multi_query|pg_query|pg_send_query|sqlite_query|odbc_exec)\s*\(|->\s*(query|exec|multi_query|unprepared)\s*\(|\b(select\s+.+\s+from|insert\s+into|update\s+\S+\s+set|delete\s+from)\b"),
         "HIGH", "HIGH", "CWE-89", "Inyección SQL: entrada no confiable en consulta",
         "La consulta SQL incorpora directamente datos controlados por el usuario. Un atacante puede leer, modificar o borrar datos de la base de datos.",
         "Usar consultas parametrizadas (PDO::prepare con marcadores o el query builder/Eloquent de Laravel con bindings). Nunca concatenar ni interpolar entrada del usuario en SQL.",
         "Probar el parámetro con una comilla simple (') y con 1 OR 1=1: la respuesta no debe variar ni mostrar errores SQL; añadir una prueba unitaria con valores maliciosos.",
         (OWASP_A03, cwe_url("CWE-89")), exclude=R(r"(?i)->prepare\s*\(|\?\s*['\"]?\s*\)|:\w+\b.*execute|bindParam|bindValue"), taint="required"),
    Rule("php.sql-injection.string-building", PHP,
         R(r"(?i)([\"'][^\"']*\b(select\s+.+\s+from|insert\s+into|update\s+\S+\s+set|delete\s+from|where\s+\w+\s*=)\b[^\"']*[\"']\s*\.\s*\$\w+|\"[^\"]*\b(select\s+.+\s+from|insert\s+into|update\s+\S+\s+set|delete\s+from|where\s+\w+\s*=)\b[^\"]*\{?\$\w+)"),
         "HIGH", "MEDIUM", "CWE-89", "Construcción dinámica de SQL con variables",
         "Se construye una sentencia SQL concatenando o interpolando variables. Si alguna procede del usuario, existe inyección SQL.",
         "Sustituir la concatenación por consultas preparadas con parámetros enlazados.",
         "Revisar el origen de cada variable de la consulta y cubrir el caso con una prueba de inyección.",
         (OWASP_A03, cwe_url("CWE-89")), exclude=R(r"(?i)->prepare\s*\("), taint="upgrade"),
    Rule("php.laravel.raw-sql-interpolation", PHP,
         R(r"(?i)(DB::(raw|select|statement|unprepared|insert|update|delete)|->(whereRaw|selectRaw|orderByRaw|havingRaw|groupByRaw|fromRaw))\s*\(\s*(\"[^\"]*\$\w+|['\"][^'\"]*['\"]\s*\.\s*\$)"),
         "HIGH", "MEDIUM", "CWE-89", "Laravel: SQL crudo con variables interpoladas",
         "Las expresiones *Raw y DB::raw no escapan su contenido. Interpolar variables abre la puerta a inyección SQL.",
         "Pasar los valores como bindings: DB::select('... where id = ?', [$id]) o ->whereRaw('col = ?', [$valor]).",
         "Comprobar que todas las llamadas Raw usan marcadores ? o :nombre con array de bindings.",
         (OWASP_A03, cwe_url("CWE-89")), taint="upgrade"),
    Rule("php.xss.reflected", PHP,
         R(r"(?i)(\becho\b|\bprint\b|<\?=|\bprintf\s*\(|\bdie\s*\(|\bexit\s*\()"),
         "HIGH", "HIGH", "CWE-79", "XSS reflejado: salida de entrada del usuario sin escapar",
         "Se imprime en la respuesta HTML un valor controlado por el usuario sin codificarlo. Permite ejecutar JavaScript en el navegador de la víctima.",
         "Escapar toda salida con htmlspecialchars($v, ENT_QUOTES, 'UTF-8') (o {{ }} en Blade). Validar la entrada contra una lista blanca.",
         "Enviar <script>alert(1)</script> y \"><svg onload=alert(1)> en el parámetro: debe mostrarse como texto, no ejecutarse.",
         (OWASP_A03, cwe_url("CWE-79")), exclude=PHP_SANITIZERS, taint="required"),
    Rule("php.code-injection.eval", PHP, R(r"(?<![\w>$])eval\s*\("),
         "HIGH", "MEDIUM", "CWE-95", "Uso de eval()",
         "eval() ejecuta código PHP arbitrario. Cualquier dato externo que llegue a eval permite ejecución remota de código.",
         "Eliminar eval(); usar estructuras de datos, mapas de funciones permitidas o json_decode según el caso.",
         "Confirmar que eval() ha desaparecido del código (grep) y que la funcionalidad se cubre con pruebas.",
         (OWASP_A03, cwe_url("CWE-95")), taint="upgrade", extra={"tainted_severity": "CRITICAL"}),
    Rule("php.command-injection", PHP, R(r"(?i)\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|`[^`]*\$"),
         "CRITICAL", "HIGH", "CWE-78", "Inyección de comandos del sistema operativo",
         "Se ejecuta un comando del sistema con datos controlados por el usuario: ejecución remota de comandos en el servidor.",
         "Evitar ejecutar comandos; si es imprescindible, usar una lista blanca de argumentos y escapeshellarg() en cada uno, o APIs nativas de PHP.",
         "Probar el parámetro con ;id y $(id): no debe ejecutarse ningún comando adicional.",
         (OWASP_A03, cwe_url("CWE-78")), exclude=R(r"escapeshellarg\s*\("), taint="required"),
    Rule("php.command-execution.dynamic", PHP, R(r"(?i)\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$"),
         "MEDIUM", "MEDIUM", "CWE-78", "Ejecución de comando con argumentos dinámicos",
         "Se ejecuta un comando del sistema con variables. Si alguna puede ser influida externamente, hay riesgo de inyección.",
         "Escapar cada argumento con escapeshellarg() o sustituir por funciones nativas.",
         "Trazar el origen de las variables del comando.",
         (cwe_url("CWE-78"),), exclude=R(r"escapeshellarg\s*\(")),
    Rule("php.file-inclusion", PHP, R(r"(?i)\b(include|include_once|require|require_once)\b"),
         "CRITICAL", "HIGH", "CWE-98", "Inclusión de fichero controlada por el usuario (LFI/RFI)",
         "La ruta de include/require depende de la entrada del usuario: lectura de ficheros arbitrarios o ejecución de código.",
         "Usar un mapa fijo de vistas/módulos permitidos; nunca construir rutas de include con entrada externa.",
         "Probar ../../../../etc/passwd y php://filter en el parámetro: debe rechazarse.",
         (OWASP_A03, cwe_url("CWE-98")), taint="required"),
    Rule("php.path-traversal", PHP, R(r"(?i)\b(file_get_contents|fopen|readfile|file|unlink|file_put_contents|copy|rename|fpassthru|parse_ini_file|show_source|highlight_file)\s*\("),
         "HIGH", "HIGH", "CWE-22", "Recorrido de directorios en operación de fichero",
         "Una operación de fichero usa una ruta derivada de la entrada del usuario sin normalizar ni restringir.",
         "Resolver con realpath() y verificar que queda dentro de un directorio base permitido; usar basename() para nombres.",
         "Probar ../ y rutas absolutas en el parámetro; deben rechazarse.",
         (OWASP_A01, cwe_url("CWE-22")), exclude=R(r"basename\s*\(|realpath\s*\("), taint="required"),
    Rule("php.ssrf", PHP, R(r"(?i)\b(curl_init|CURLOPT_URL|get_headers|fsockopen)\b"),
         "HIGH", "HIGH", "CWE-918", "SSRF: petición saliente a URL controlada por el usuario",
         "El servidor realiza peticiones a una URL aportada por el usuario; permite acceder a servicios internos.",
         "Validar la URL contra una lista blanca de hosts y bloquear rangos internos y metadatos.",
         "Probar http://127.0.0.1 y http://169.254.169.254 como destino: deben rechazarse.",
         (OWASP_A10, cwe_url("CWE-918")), taint="required"),
    Rule("php.insecure-deserialization", PHP, R(r"(?i)\bunserialize\s*\("),
         "HIGH", "HIGH", "CWE-502", "Deserialización insegura de datos no confiables",
         "unserialize() sobre datos del usuario permite inyección de objetos PHP (POP chains) y ejecución de código.",
         "Usar json_decode(); si se requiere unserialize, pasar ['allowed_classes' => false].",
         "Confirmar que ningún flujo de entrada llega a unserialize() sin allowed_classes=false.",
         (OWASP_A08, cwe_url("CWE-502")), exclude=R(r"allowed_classes"), taint="required"),
    Rule("php.extract-input", PHP, R(r"(?i)\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"),
         "HIGH", "HIGH", "CWE-621", "extract() sobre entrada del usuario",
         "extract() crea variables a partir de la entrada y permite sobrescribir variables internas (p. ej. de autorización).",
         "Leer explícitamente cada parámetro necesario y validar su tipo.",
         "Enviar un parámetro con el nombre de una variable interna (p. ej. is_admin=1) y verificar que no la altera.",
         (cwe_url("CWE-621"),)),
    Rule("php.open-redirect", PHP, R(r"(?i)header\s*\(\s*['\"]location\s*:"),
         "MEDIUM", "HIGH", "CWE-601", "Redirección abierta",
         "La cabecera Location se construye con entrada del usuario: permite redirigir a sitios de phishing.",
         "Redirigir solo a rutas relativas internas o a una lista blanca de dominios.",
         "Probar el parámetro con https://ejemplo-malicioso.test: no debe redirigir fuera del dominio.",
         (cwe_url("CWE-601"),), taint="required"),
    Rule("php.weak-password-hash", PHP, R(r"(?i)\b(md5|sha1|crc32)\s*\(\s*[^)]*(pass|pwd|clave|contrase)"),
         "HIGH", "HIGH", "CWE-916", "Hash de contraseña débil (MD5/SHA1)",
         "MD5/SHA1 son rápidos y sin sal: las contraseñas se pueden romper por fuerza bruta.",
         "Usar password_hash($pwd, PASSWORD_ARGON2ID o PASSWORD_BCRYPT) y password_verify().",
         "Verificar que el almacenamiento usa el prefijo $2y$ o $argon2id$.",
         (OWASP_A02, cwe_url("CWE-916"))),
    Rule("php.tls-verification-disabled", PHP, R(r"(?i)CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*(false|0)\b|['\"]verify['\"]\s*=>\s*false"),
         "MEDIUM", "HIGH", "CWE-295", "Verificación TLS deshabilitada",
         "Desactivar la verificación del certificado permite ataques de intermediario.",
         "Mantener CURLOPT_SSL_VERIFYPEER=true y VERIFYHOST=2; usar el almacén de CAs interno si hay certificados propios.",
         "Configurar un proxy con certificado no confiable: la petición debe fallar.",
         (OWASP_A02, cwe_url("CWE-295"))),
    Rule("php.insecure-random", PHP, R(r"(?i)\b(rand|mt_rand|uniqid|lcg_value|str_shuffle)\s*\(.*(token|secret|password|salt|nonce|otp|csrf)|(token|secret|password|salt|nonce|otp|csrf)\w*\s*=.*\b(rand|mt_rand|uniqid|str_shuffle)\s*\("),
         "MEDIUM", "MEDIUM", "CWE-338", "Generador aleatorio no criptográfico para valores de seguridad",
         "rand/mt_rand/uniqid son predecibles; no deben generar tokens, contraseñas ni sales.",
         "Usar random_bytes() o random_int() (o Str::random en Laravel).",
         "Revisar que todos los tokens se generan con funciones criptográficas.",
         (OWASP_A02, cwe_url("CWE-338"))),
    Rule("php.xxe", PHP, R(r"(?i)libxml_disable_entity_loader\s*\(\s*false|LIBXML_NOENT|LIBXML_DTDLOAD"),
         "MEDIUM", "MEDIUM", "CWE-611", "Procesamiento XML con entidades externas",
         "Habilitar entidades externas permite XXE: lectura de ficheros locales y SSRF.",
         "No usar LIBXML_NOENT/LIBXML_DTDLOAD con XML no confiable.",
         "Enviar un XML con <!ENTITY xxe SYSTEM \"file:///etc/passwd\">: no debe resolverse.",
         (cwe_url("CWE-611"),)),
    Rule("php.display-errors", PHP, R(r"(?i)ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]?(1|on|true)|error_reporting\s*\(\s*E_ALL\s*\)\s*;.*display"),
         "LOW", "HIGH", "CWE-209", "Errores mostrados al usuario",
         "Mostrar errores en producción revela rutas, consultas y versiones.",
         "Desactivar display_errors en producción y registrar los errores en el log.",
         "Forzar un error y comprobar que la respuesta no muestra trazas.",
         (OWASP_A05, cwe_url("CWE-209"))),
    Rule("php.phpinfo", PHP, R(r"(?i)\bphpinfo\s*\("),
         "LOW", "HIGH", "CWE-200", "phpinfo() expuesto",
         "phpinfo() revela configuración, rutas, variables de entorno y versiones.",
         "Eliminar la llamada del código desplegable.",
         "Buscar phpinfo( en el código y en rutas públicas.",
         (OWASP_A05, cwe_url("CWE-200"))),
    Rule("php.laravel.unescaped-output", PHP, R(r"\{!!\s*(?!\s*(csrf_field|method_field)\s*\()"),
         "MEDIUM", "LOW", "CWE-79", "Blade: salida sin escapar {!! !!}",
         "{!! !!} imprime HTML sin escapar; si el contenido incluye datos de usuario, existe XSS almacenado o reflejado.",
         "Usar {{ }} o sanear el HTML con una librería de lista blanca antes de imprimirlo.",
         "Revisar el origen de cada variable impresa con {!! !!}.",
         (cwe_url("CWE-79"),), path_filter=R(r"\.blade\.php$"), taint="upgrade", extra={"tainted_severity": "HIGH"}),

    # ======================================================================= JavaScript / TypeScript
    Rule("js.xss.dom-sink", JS, R(r"\.(innerHTML|outerHTML)\s*\+?=|\bdocument\.write(ln)?\s*\(|\.insertAdjacentHTML\s*\(|\$\([^)]*\)\s*\.\s*(html|append|prepend|after|before)\s*\("),
         "HIGH", "HIGH", "CWE-79", "XSS basado en DOM: fuente no confiable hacia sumidero HTML",
         "Un valor controlado por el atacante (URL, mensaje, parámetro) se inserta como HTML en el DOM.",
         "Usar textContent/innerText o crear nodos con createElement; si se necesita HTML, sanearlo con DOMPurify.",
         "Abrir la página con #<img src=x onerror=alert(1)> o ?q=<svg onload=alert(1)>: no debe ejecutarse.",
         (OWASP_A03, cwe_url("CWE-79")), exclude=JS_SANITIZERS, taint="required"),
    Rule("js.xss.inner-html", JS, R(r"\.(innerHTML|outerHTML)\s*\+?=\s*(?![\"'][^\"'+]*[\"']\s*;?\s*$)(?!`[^`$]*`\s*;?\s*$)\S"),
         "MEDIUM", "LOW", "CWE-79", "Asignación dinámica a innerHTML",
         "Se asigna a innerHTML un valor no literal. Si contiene datos externos, existe XSS.",
         "Preferir textContent o DOMPurify.sanitize() antes de asignar HTML.",
         "Trazar el origen del valor asignado.",
         (cwe_url("CWE-79"),), exclude=JS_SANITIZERS),
    Rule("js.xss.react-dangerously-set", JS, R(r"dangerouslySetInnerHTML"),
         "MEDIUM", "LOW", "CWE-79", "React: dangerouslySetInnerHTML",
         "Inserta HTML sin escapar. Requiere que el contenido esté saneado.",
         "Sanear con DOMPurify o renderizar como texto.",
         "Revisar el origen del contenido.",
         (cwe_url("CWE-79"),), exclude=JS_SANITIZERS),
    Rule("js.code-injection.eval", JS, R(r"(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(|\bset(Timeout|Interval)\s*\(\s*[\"'`]"),
         "HIGH", "MEDIUM", "CWE-95", "Evaluación dinámica de código (eval / new Function)",
         "eval/new Function/setTimeout con cadena ejecutan código arbitrario; con datos externos es ejecución de código.",
         "Eliminar la evaluación dinámica; usar JSON.parse para datos y funciones explícitas para lógica.",
         "Confirmar que no quedan llamadas a eval/new Function.",
         (OWASP_A03, cwe_url("CWE-95")), taint="upgrade", extra={"tainted_severity": "CRITICAL"}),
    # execFile/spawn con array de argumentos no invocan shell: solo se marcan con shell:true.
    Rule("js.command-injection", JS, R(r"\b(exec|execSync)\s*\(|\b(spawn|spawnSync|execFile|execFileSync)\s*\([^)]*shell\s*:\s*true"),
         "CRITICAL", "HIGH", "CWE-78", "Inyección de comandos (child_process)",
         "Se ejecuta un comando del sistema con datos de la petición: ejecución remota de comandos.",
         "Usar execFile/spawn con array de argumentos fijo y validar contra lista blanca; nunca shell:true con entrada externa.",
         "Probar ;id y `id` en el parámetro: no debe ejecutarse nada adicional.",
         (OWASP_A03, cwe_url("CWE-78")), taint="required", file_requires=R(r"child_process")),
    Rule("js.command-execution.dynamic", JS, R(r"\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|[^,)]*\+\s*[\w$])"),
         "MEDIUM", "MEDIUM", "CWE-78", "Comando construido dinámicamente (child_process)",
         "Se construye un comando de shell por concatenación/plantilla.",
         "Usar execFile/spawn con argumentos separados.",
         "Trazar el origen de las variables del comando.",
         (cwe_url("CWE-78"),), file_requires=R(r"child_process")),
    Rule("js.sql-injection", JS, R(r"(?i)\.(query|execute|raw|run|all|get|prepare)\s*\(\s*(`[^`]*\b(select|insert|update|delete)\b[^`]*\$\{|[\"'][^\"']*\b(select|insert|update|delete)\b[^\"']*[\"']\s*\+)|`[^`]*\b(select\s+.+\s+from|insert\s+into|update\s+\S+\s+set|delete\s+from)\b[^`]*\$\{"),
         "HIGH", "MEDIUM", "CWE-89", "Inyección SQL: consulta construida con concatenación/plantilla",
         "La consulta SQL se construye con variables; si proceden de la petición, existe inyección SQL.",
         "Usar consultas parametrizadas (marcadores ? / $1) o el query builder del ORM.",
         "Probar ' OR '1'='1 en el parámetro: el resultado no debe cambiar.",
         (OWASP_A03, cwe_url("CWE-89")), taint="upgrade"),
    Rule("js.path-traversal", JS, R(r"\b(readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|sendFile|download|readdir)\s*\("),
         "HIGH", "HIGH", "CWE-22", "Recorrido de directorios con ruta de la petición",
         "Una operación de fichero usa una ruta que procede de la petición.",
         "Normalizar con path.resolve y comprobar que queda bajo el directorio base; usar path.basename para nombres.",
         "Probar ../../etc/passwd en el parámetro.",
         (OWASP_A01, cwe_url("CWE-22")), exclude=R(r"path\.basename\s*\("), taint="required"),
    Rule("js.open-redirect", JS, R(r"\bres\.redirect\s*\(|\b(window\.)?location(\.href)?\s*=(?!=)|\blocation\.(assign|replace)\s*\("),
         "MEDIUM", "HIGH", "CWE-601", "Redirección abierta",
         "La redirección usa un destino controlado por el usuario.",
         "Redirigir solo a rutas internas o a una lista blanca.",
         "Probar un dominio externo como destino.",
         (cwe_url("CWE-601"),), taint="required", extra={"taint_scope": "after"}),
    Rule("js.nosql-injection", JS, R(r"\.(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|countDocuments)\s*\(\s*req\.(query|body|params)\b"),
         "HIGH", "MEDIUM", "CWE-943", "Inyección NoSQL: objeto de la petición usado como filtro",
         "Pasar req.query/req.body directamente como filtro permite operadores como $ne/$gt.",
         "Construir el filtro con campos explícitos y tipos validados; usar sanitizadores como mongo-sanitize.",
         "Enviar {\"$ne\": null} en el parámetro: no debe devolver todos los registros.",
         (OWASP_A03, cwe_url("CWE-943"))),
    Rule("js.tls-verification-disabled", JS, R(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
         "MEDIUM", "HIGH", "CWE-295", "Verificación TLS deshabilitada",
         "Desactivar la validación de certificados permite ataques de intermediario.",
         "Eliminar rejectUnauthorized:false y configurar la CA interna si es necesario.",
         "Probar contra un certificado no confiable: la conexión debe fallar.",
         (OWASP_A02, cwe_url("CWE-295"))),
    Rule("js.jwt-none-algorithm", JS, R(r"algorithms\s*:\s*\[[^\]]*['\"]none['\"]|verify\s*:\s*false"),
         "HIGH", "HIGH", "CWE-347", "JWT sin verificación de firma",
         "Aceptar el algoritmo 'none' o desactivar la verificación permite falsificar tokens.",
         "Fijar explícitamente el algoritmo esperado (p. ej. ['RS256']) y verificar siempre la firma.",
         "Enviar un JWT con alg:none: debe rechazarse.",
         (cwe_url("CWE-347"),)),
    Rule("js.insecure-random", JS, R(r"(?i)Math\.random\s*\(\s*\).*(token|secret|password|session|nonce|salt|otp|key)|(token|secret|password|session|nonce|salt|otp)\w*\s*[:=].*Math\.random\s*\("),
         "MEDIUM", "MEDIUM", "CWE-338", "Math.random() para valores de seguridad",
         "Math.random() no es criptográficamente seguro.",
         "Usar crypto.getRandomValues() o crypto.randomBytes()/randomUUID().",
         "Revisar la generación de todos los tokens.",
         (OWASP_A02, cwe_url("CWE-338"))),
    Rule("js.postmessage-wildcard", JS, R(r"\.postMessage\s*\([^)]*,\s*['\"]\*['\"]"),
         "MEDIUM", "MEDIUM", "CWE-345", "postMessage con origen comodín",
         "Enviar mensajes a '*' puede filtrar datos a ventanas de otros orígenes.",
         "Indicar el origen exacto de destino y validar event.origin al recibir.",
         "Revisar que cada postMessage especifica targetOrigin.",
         (cwe_url("CWE-345"),)),
    Rule("js.sensitive-localstorage", JS, R(r"(?i)(localStorage|sessionStorage)\.setItem\s*\(\s*['\"][^'\"]*(token|jwt|secret|password|auth)"),
         "LOW", "MEDIUM", "CWE-922", "Credenciales en almacenamiento web",
         "localStorage/sessionStorage es accesible por cualquier script de la página (XSS).",
         "Usar cookies HttpOnly+Secure+SameSite para tokens de sesión.",
         "Comprobar en DevTools que no se guardan tokens en el almacenamiento web.",
         (cwe_url("CWE-922"),)),
    Rule("js.cors-wildcard", JS, R(r"(?i)Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*['\"]|cors\s*\(\s*\{\s*origin\s*:\s*(true|['\"]\*['\"])"),
         "LOW", "MEDIUM", "CWE-942", "CORS permisivo",
         "Permitir cualquier origen expone la API a sitios de terceros.",
         "Restringir los orígenes permitidos a una lista explícita.",
         "Enviar Origin: https://otro.test y comprobar que no se refleja.",
         (OWASP_A05, cwe_url("CWE-942"))),

    # ======================================================================= HTML (incluye vistas PHP y componentes)
    Rule("html.external-script-without-sri", HTML, R(r"(?i)<script\b[^>]*\bsrc\s*=\s*['\"]?(https?:)?//"),
         "LOW", "HIGH", "CWE-353", "Script externo sin Subresource Integrity",
         "Un script de un CDN sin atributo integrity puede ser sustituido si el CDN se compromete.",
         "Añadir integrity=\"sha384-...\" y crossorigin=\"anonymous\", o servir el recurso localmente.",
         "Comprobar que cada <script src> externo tiene atributo integrity.",
         (OWASP_A08, cwe_url("CWE-353")), exclude=R(r"(?i)\bintegrity\s*=")),
    Rule("html.mixed-content", HTML, R(r"(?i)<(script|link|iframe|img|form|embed|object)\b[^>]*\b(src|href|action|data)\s*=\s*['\"]http://(?!localhost|127\.0\.0\.1)"),
         "MEDIUM", "HIGH", "CWE-319", "Recurso cargado por HTTP sin cifrar",
         "Cargar recursos o enviar formularios por HTTP permite interceptarlos o modificarlos.",
         "Usar siempre https:// (o rutas relativas).",
         "Inspeccionar la consola del navegador en busca de avisos de contenido mixto.",
         (OWASP_A02, cwe_url("CWE-319"))),
    Rule("html.target-blank-noopener", HTML, R(r"(?i)<a\b[^>]*\btarget\s*=\s*['\"]?_blank"),
         "LOW", "MEDIUM", "CWE-1022", "Enlace target=_blank sin rel=noopener",
         "La página abierta puede manipular window.opener (tabnabbing) en navegadores antiguos.",
         "Añadir rel=\"noopener noreferrer\".",
         "Revisar los enlaces que abren en nueva pestaña.",
         (cwe_url("CWE-1022"),), exclude=R(r"(?i)\brel\s*=\s*['\"][^'\"]*\bno(opener|referrer)")),
    Rule("html.password-autocomplete", HTML, R(r"(?i)<input\b[^>]*type\s*=\s*['\"]password['\"][^>]*autocomplete\s*=\s*['\"]on['\"]"),
         "LOW", "MEDIUM", "CWE-522", "Autocompletado forzado en campo de contraseña",
         "Forzar autocomplete=on en contraseñas en equipos compartidos expone credenciales.",
         "Usar autocomplete=\"current-password\" o \"new-password\".",
         "Revisar los formularios de credenciales.",
         (cwe_url("CWE-522"),)),

    # ======================================================================= CSS
    Rule("css.insecure-resource", CSS, R(r"(?i)(@import\s+(url\()?\s*['\"]?http://|url\(\s*['\"]?http://)"),
         "LOW", "HIGH", "CWE-319", "Recurso CSS cargado por HTTP",
         "Las hojas o recursos cargados por HTTP pueden ser modificados en tránsito.",
         "Usar https:// o rutas relativas.",
         "Revisar @import y url() en las hojas de estilo.",
         (cwe_url("CWE-319"),)),
    Rule("css.expression", CSS, R(r"(?i)\bexpression\s*\(|behavior\s*:\s*url\("),
         "LOW", "MEDIUM", "CWE-79", "Expresiones CSS ejecutables (legado IE)",
         "expression() y behavior: permiten ejecutar script en navegadores heredados.",
         "Eliminar expression()/behavior.",
         "Buscar expression( en las hojas de estilo.",
         (cwe_url("CWE-79"),)),
]

RULESET_VERSION = "2026.11.1"
