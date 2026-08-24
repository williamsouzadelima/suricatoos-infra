# Glosario — traducción de los NVTs al español

Contrato de consistencia: doce agentes traducen lotes distintos del mismo
catálogo. Sin esto, "remote attacker" se convierte en cinco cosas diferentes en
el mismo PDF. Espejo del `GLOSSARIO.md` de pt-BR.

## Términos fijos

| inglés | español |
|---|---|
| remote attacker | atacante remoto |
| attacker | atacante |
| vulnerability | vulnerabilidad |
| flaw | falla |
| finding | hallazgo |
| host | host (no traducir) |
| target | objetivo |
| scan | escaneo (verbo: escanear) |
| service | servicio |
| endpoint | endpoint (no traducir) |
| issue | problema |
| information disclosure | exposición de información |
| disclosure (de vulnerabilidad) | divulgación |
| denial of service (DoS) | denegación de servicio (DoS) |
| privilege escalation | escalada de privilegios |
| arbitrary code execution | ejecución de código arbitrario |
| buffer overflow | desbordamiento de búfer |
| cross-site scripting | cross-site scripting (no traducir; sigla XSS) |
| SQL injection | inyección de SQL |
| man-in-the-middle | man-in-the-middle (no traducir) |
| directory traversal | travesía de directorio |
| cleartext / plaintext | texto claro |
| eavesdrop | interceptar |
| bypass | eludir (sust.: elusión) |
| mitigation | mitigación |
| workaround | solución temporal |
| vendor fix | corrección del proveedor |
| patch (sust.) | parche |
| update / upgrade (verbo) | actualizar |
| deprecated | obsoleto |
| end of life (EOL) | fin de vida (EOL) |
| enabled / disabled | habilitado / deshabilitado |
| supported | compatible |
| affected | afectado |
| unauthenticated | no autenticado |
| credentials | credenciales |
| default (adj.) | predeterminado |
| request / response | solicitud / respuesta |
| header | encabezado |
| payload | payload (no traducir) |
| cipher suite | conjunto de cifrado |
| certificate | certificado |
| key exchange | intercambio de claves |
| timestamp | timestamp (no traducir) |
| banner | banner (no traducir) |
| listening | escuchando |
| open port | puerto abierto |
| is prone to | es susceptible a |
| sanitize | sanear |
| Active Check | Verificación activa |
| HTTP based detection of X | Detección de X (HTTP) |
| scanner | scanner (no traducir) |

## Lo que NO se traduce, nunca

- Identificadores: CVE-…, CWE-…, USN-…, DSA-…, RHSA-…, OID, QoD.
- Vectores CVSS (`CVSS:3.1/AV:N/…`) y números de versión.
- Nombres de producto, protocolo y RFC: OpenSSH, Apache, TLSv1.2, HTTP, SMB, LDAP.
- Nombres de archivo, rutas, directivas de configuración, comandos, código.
- URLs.
- Salida literal de herramienta (el campo `detection` suele ser eso).

## Registro

Español neutro, **impersonal y directo**, como informe técnico. Evite "usted".
Prefiera "permite que un atacante ejecute" a "podría permitir que un atacante
pudiera ejecutar". Mantenga la longitud cercana al original — el texto va dentro
de tarjetas de ancho fijo.

No invente contenido: si el original es vago, la traducción es vaga. No añada
recomendaciones que el original no hace.
