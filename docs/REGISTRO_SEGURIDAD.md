# Registro de seguridad · Sistema Alumnos

Estudiante: Nicolas Morales   Repositorio: https://github.com/nicolmoraless-ops/ev3-sistema-alumnos   Fecha: 23-11-2026

Cada fila se puede seguir hasta un **build de Jenkins** y un **commit** (identificador `VULN-xx` en el mensaje).
Las horas de Jenkins y de `TRAZABILIDAD.md` están en UTC; las de Grafana, en hora local (UTC-3).

## 1. Revisiones de seguridad realizadas

| # | Etapa del SDLC | Herramienta / técnica | Build | Resultado (resumen) |
|---|---|---|---|---|
| R1 | Código (SAST) | Bandit en el pipeline (etapa *Security Review (SAST)*) | #2 | 2 hallazgos High / 2 Medium / 1 Low → tras las correcciones, build #3: 0 / 0 / 0 |
| R2 | Dependencias (SCA) | pip-audit en el pipeline (etapa *Dependency Management*) | #2 | 19 vulnerabilidades en 4 paquetes (Flask, Werkzeug, Jinja2, gunicorn) → build #7: 0 |
| R3 | Pruebas dinámicas (DAST) | OWASP ZAP 2.16.1 sobre staging (spider + pasivo + activo) | #2 | 3 High / 3 Medium / 1 Low → build #3: 0 / 0 / 0 (solo informativas) |
| R4 | Revisión manual | Lectura de `app.py` | — | Además de lo anterior: clave del admin = `admin`, sin token anti-CSRF, sin límite de intentos de login, sin cabeceras de seguridad, inyección en logs |
| R5 | Producción | Grafana + Prometheus (dashboard *Sistema Alumnos - Producción (seguridad)* y 2 reglas de alerta) | — | Incidente detectado el 23-11 a las 16:52 (ver sección 4) |

## 2. Vulnerabilidades identificadas y corregidas

| ID | Vulnerabilidad (CWE) | Detectada por | Ubicación | Riesgo | Corrección aplicada | Commit | Build que lo verifica |
|---|---|---|---|---|---|---|---|
| VULN-01 | Credenciales y clave en el código (CWE-798) + hash débil MD5 sin sal (CWE-327/CWE-916); la clave del admin era `admin` (CWE-521) | Bandit B105 y B324 + revisión manual + fuerza bruta en producción | `app.py:20`, `:22`, `:221` | Alto | `SECRET_KEY` desde variable de entorno (o aleatoria con `secrets`); hash de la clave del admin desde `ADMIN_CLAVE_HASH` con `werkzeug.security` (scrypt/pbkdf2 con sal); comparación con `hmac.compare_digest`; sin hash configurado, el acceso admin queda deshabilitado | `3ba90f0` | #3 |
| VULN-02 | Inyección SQL (CWE-89) + exposición de la consulta y del error (CWE-209) | Bandit B608 + ZAP "SQL Injection" (High) + ataque en producción | `app.py:205`, `:209` | Alto | Consulta parametrizada `LIKE ?`; error genérico sin detalles y registro interno con `logger.exception` | `2672b1b` | #3 |
| VULN-03 | XSS reflejado (CWE-79) | ZAP "Cross Site Scripting (Reflected)" y "(DOM Based)" (High) + ataque en producción | `app.py:154` | Alto | `markupsafe.escape()` del parámetro `name` antes de insertarlo en el HTML | `5ee5eae` | #3 |
| VULN-04 | Depurador de Werkzeug activo (CWE-489/CWE-94) y escucha en todas las interfaces (CWE-605) | Bandit B201 (High) y B104 (Medium) | `app.py:241` | Alto | `debug=False` y `host="127.0.0.1"` en `app.run()`; los despliegues usan gunicorn | `1caf652` | #3 |
| VULN-05 | Falta de protección CSRF en el login (CWE-352) | ZAP "Absence of Anti-CSRF Tokens" (Medium) | `app.py:69`, `/login` | Medio | Token aleatorio por sesión en un campo oculto `csrf_token`, validado con `hmac.compare_digest` (HTTP 400 si no coincide) | `56ca534` | #3 |
| VULN-06 | Sin límite de intentos de autenticación (CWE-307) | Revisión manual + incidente en Grafana (fuerza bruta exitosa) | `/login` | Alto | Máximo 5 intentos fallidos por IP en 5 minutos; luego HTTP 429 (configurable por entorno) | `3172d97` | #3 y ataque de verificación (26 intentos bloqueados) |
| VULN-07 | Faltan cabeceras de seguridad (CWE-693, CWE-1021), cookie sin SameSite e inyección en logs (CWE-117) | ZAP "CSP Header Not Set", "Missing Anti-clickjacking Header" (Medium) y "X-Content-Type-Options Header Missing" (Low) + revisión manual | `app.py:125`, `:225` | Medio | CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/COEP/CORP; cookie `HttpOnly; SameSite=Strict`; usuario registrado con `%r` y truncado | `6679d97` | #3 |
| VULN-08 | Dependencias con 19 CVE conocidas (CWE-1395) | pip-audit + Dependabot | `requirements.txt` | Alto | Actualización con los PR #1–#6 de Dependabot (ver sección 5) | merges `1fc384c` … `bafb2c5` | #7 |

Riesgo aceptado: `/metrics` no tiene autenticación; en este laboratorio solo lo consulta Prometheus por la red interna de Docker. En producción real se protegería con red privada o autenticación.

## 3. Resultados de OWASP ZAP

| Alerta de ZAP | Riesgo | URL de ejemplo | VULN relacionada | Cómo se mitiga | ¿Mitigada? Build |
|---|---|---|---|---|---|
| SQL Injection | High | `/alumnos/buscar?nombre='` | VULN-02 | Consulta parametrizada y error genérico | Sí · #3 |
| Cross Site Scripting (Reflected) | High | `/hello?name=</h1><script>alert(1);</script><h1>` | VULN-03 | Escape HTML de `name` + CSP | Sí · #3 |
| Cross Site Scripting (DOM Based) | High | `/hello?name=<script>alert(5397)</script>` | VULN-03 | Escape HTML de `name` + CSP | Sí · #3 |
| Absence of Anti-CSRF Tokens | Medium | `/` (formulario de login) | VULN-05 | Token `csrf_token` por sesión | Sí · #3 |
| Content Security Policy (CSP) Header Not Set | Medium | `/` (5 URL) | VULN-07 | Cabecera `Content-Security-Policy` | Sí · #3 |
| Missing Anti-clickjacking Header | Medium | `/` (3 URL) | VULN-07 | `X-Frame-Options: DENY` y `frame-ancestors 'none'` | Sí · #3 |
| X-Content-Type-Options Header Missing | Low | `/` (6 URL) | VULN-07 | `X-Content-Type-Options: nosniff` | Sí · #3 |

Build #3 y siguientes: High=0, Medium=0, Low=0. Solo quedan alertas informativas ("Session Management Response Identified", "User Agent Fuzzer"), que no son vulnerabilidades.

## 4. Monitoreo e incidentes

| Hora | Panel / métrica de Grafana | Qué se observó | Entorno | Clasificación | Acción de respuesta | Verificación |
|---|---|---|---|---|---|---|
| 16:52 | *Logins fallidos (último minuto)*: `increase(login_fallidos_total[1m])`; alerta "Posible fuerza bruta en /login" → **Firing** | 65 logins fallidos en 1 minuto y logins **exitosos**: el atacante obtuvo la clave `admin` en 31 intentos | Producción `1.0.1+84c8311` | Incidente **alto**: compromiso de credenciales (CWE-307/CWE-521) | Contención: la versión vulnerable deja de pasar el gate. Erradicación: VULN-01 (credenciales fuera del código, hash seguro) y VULN-06 (límite de intentos). Recuperación: despliegue de `1.0.7+bafb2c5` (build #7) | 17:57: mismo ataque → 0 claves encontradas, 26 intentos bloqueados (HTTP 429 en *Errores HTTP 4xx/5xx*), *exitosos* = 0 |
| 16:52 | *Peticiones sospechosas por tipo de ataque*: `peticiones_sospechosas_total{tipo}`; alerta "Peticiones con patrones de ataque" → **Firing** | Peticiones `sqli` y `xss`; la inyección SQL expuso la estructura de la base y el XSS se reflejó sin escapar | Producción `1.0.1+84c8311` | Incidente **alto**: inyección SQL y XSS explotables (CWE-89/CWE-79) | VULN-02 (consulta parametrizada) y VULN-03 (escape HTML), desplegadas en el build #7 | 17:57: la inyección no devuelve datos internos y el script queda escapado; Grafana sigue detectando y alertando los intentos |

Proceso seguido: **detección** (alerta de Grafana + dashboard) → **análisis** (paneles por tipo de ataque, endpoints y códigos HTTP; logs de la app) → **clasificación** (severidad alta, entorno producción) → **respuesta** (correcciones VULN-01..07 y dependencias por el pipeline con gate) → **verificación** (repetición del ataque contra la nueva versión).

## 5. Gestión de dependencias

| Paquete | Versión inicial | Vulnerabilidades (IDs) | Versión final | Origen del cambio (PR de Dependabot / manual) | ¿Pruebas, pip-audit y ZAP siguen OK? Build |
|---|---|---|---|---|---|
| Flask | 2.2.2 | CVE-2023-30861, CVE-2026-27205 | 3.1.3 | PR #1 de Dependabot | Build #4 FAILURE: Flask 3.1.3 exige Werkzeug ≥ 3.1 (`ResolutionImpossible`); el pipeline bloqueó la combinación incompatible. OK en #7 |
| Werkzeug | 2.2.2 | CVE-2023-23934, CVE-2023-25577, CVE-2023-46136, CVE-2024-34069, CVE-2024-49766, CVE-2024-49767, CVE-2025-66221, CVE-2026-102598, CVE-2026-21860, CVE-2026-27199 | 3.1.9 | PR #5 de Dependabot | #5: 9/9 pruebas, pip-audit baja de 19 a 7 · OK en #7 |
| Jinja2 | 3.1.2 | CVE-2024-22195, CVE-2024-34064, CVE-2024-56201, CVE-2024-56326, CVE-2025-27516 | 3.1.6 | PR #2 de Dependabot (rebase automático tras conflictos) | OK · #7 |
| gunicorn | 21.2.0 | CVE-2024-1135, CVE-2024-6827 | 27.0.1 | PR #4 de Dependabot | #6: 9/9 pruebas, pip-audit 5 · OK en #7 |
| prometheus-client | 0.17.1 | — | 0.26.0 | PR #3 de Dependabot | OK · #7 |
| pytest (solo pruebas) | 8.3.4 | — | 9.2.0 | PR #6 de Dependabot | OK · #7 |

Cómo se verificó que las actualizaciones no introducen vulnerabilidades: cada PR fusionado dispara el pipeline completo. Pruebas funcionales (9/9), Bandit, **pip-audit sobre las nuevas versiones** y OWASP ZAP sobre staging. El gate solo despliega en producción si todo queda limpio. Resultado del build #7: pip-audit "No known vulnerabilities found", ZAP 0/0/0, Bandit 0/0/0 → desplegado `1.0.7+bafb2c5`.

## 6. Trazabilidad

El registro completo lo genera Jenkins en cada build (`scripts/trazabilidad.py` → artefacto `reports/TRAZABILIDAD.md`).

| Build | Versión | Commit | Pruebas | Bandit H/M/L | pip-audit | ZAP H/M/L | Resultado | Producción |
|---|---|---|---|---|---|---|---|---|
| 1 | 1.0.1+84c8311 | `84c8311` Inicio | 9/9 OK | n/a | n/a | n/a | SUCCESS | 1.0.1+84c8311 |
| 2 | 1.0.2+6f36e38 | `6f36e38` SEC: etapas de seguridad | 9/9 OK | 2/2/1 | 19 vuln. | 3/3/1 | UNSTABLE | no desplegado |
| 3 | 1.0.3+6679d97 | `6679d97` VULN-01..07 | 9/9 OK | 0/0/0 | 19 vuln. | 0/0/0 | UNSTABLE | no desplegado |
| 4 | 1.0.4+1fc384c | PR #1 Flask | n/a | n/a | n/a | n/a | FAILURE | no desplegado |
| 5 | 1.0.5+1f46c6a | PR #5 Werkzeug | 9/9 OK | 0/0/0 | 7 vuln. | 0/0/0 | UNSTABLE | no desplegado |
| 6 | 1.0.6+d942a80 | PR #4 gunicorn y #6 pytest | 9/9 OK | 0/0/0 | 5 vuln. | 0/0/0 | UNSTABLE | no desplegado |
| 7 | 1.0.7+bafb2c5 | PR #2 Jinja2 y #3 prometheus-client | 9/9 OK | 0/0/0 | 0 vuln. | 0/0/0 | SUCCESS | **1.0.7+bafb2c5** |

| Actividad | Hallazgo | Build que lo detectó | Commit / PR que lo resolvió | Build que lo verificó | Versión en producción |
|---|---|---|---|---|---|
| Revisión de seguridad (Bandit) | B324 MD5 y B201 `debug=True` (High), B608 SQL y B104 bind (Medium), B105 clave (Low) | #2 | `3ba90f0` VULN-01, `2672b1b` VULN-02, `1caf652` VULN-04 | #3 | 1.0.7+bafb2c5 |
| Prueba automatizada (OWASP ZAP) | SQL Injection, XSS Reflected/DOM (High), CSRF, CSP, anti-clickjacking (Medium), nosniff (Low) | #2 | `2672b1b`, `5ee5eae`, `56ca534`, `6679d97` | #3 | 1.0.7+bafb2c5 |
| Gestión de dependencias (Dependabot) | 19 CVE en Flask, Werkzeug, Jinja2 y gunicorn | #2 (pip-audit) | PR #1, #5, #2, #4, #3, #6 | #7 | 1.0.7+bafb2c5 |
| Monitoreo (Grafana) | Fuerza bruta exitosa, SQLi y XSS en producción | Alertas de Grafana 16:52 | VULN-01, 02, 03, 06 | Ataque de verificación 17:57 | 1.0.7+bafb2c5 |
