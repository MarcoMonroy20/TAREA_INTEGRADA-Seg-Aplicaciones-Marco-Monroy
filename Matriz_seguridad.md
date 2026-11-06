# Matriz de seguridad del portal universitario

La matriz relaciona el riesgo con su causa, el control implementado y una prueba reproducible. Los identificadores corresponden a `pruebas.py`. Los resultados completos se conservan en `evidencias/resultados_pruebas.json`.

| Riesgo | Causa raíz | Corrección | Verificación | Estado |
|---|---|---|---|---|
| Datos inválidos o ambiguos | Aceptar formatos y rangos sin restricciones | Normalización NFC; validación de nombres, correo, carnet, búsqueda y nota | 01, 17 y 18; valores válidos aceptados e inválidos rechazados sin modificar la base | Aprobado |
| SQL Injection | Construcción de consultas por concatenación | Marcadores `?` y parámetros separados; búsqueda literal con escape de comodines | 02 y 03; la consulta vulnerable devuelve 2 filas y la parametrizada 0 para la misma entrada | Aprobado |
| XSS almacenado o reflejado | Interpretar entradas de usuarios como HTML | Autoescape de Jinja; atributos entre comillas; CSP sin scripts | 04; comentario guardado como dato, salida codificada y cero etiquetas script activas | Aprobado |
| Inyección de comandos | Concatenar opciones o nombres en una orden del sistema | Reportes con `csv` y `zipfile` sin shell; formato en lista permitida y nombres fijos | 05; ZIP válido y formato `zip; echo INYECTADO` rechazado con HTTP 400 | Aprobado |
| Recuperación masiva de contraseñas | Texto claro o hash rápido sin costo especializado | Argon2id con m=19456 KiB, t=2, p=1 y sal aleatoria de 16 bytes | 06 y 07; hashes distintos, verificación correcta y contraseña incorrecta rechazada | Aprobado |
| Lectura o alteración de expedientes | Información académica sin protección ni autenticación criptográfica | AES-256-GCM; nonce de 12 bytes; AAD asociado al identificador | 08; lectura autorizada correcta, alteración e intercambio rechazados | Aprobado |
| Secretos incorporados al código | Claves fijas o distribuidas con el repositorio | Variables de entorno con origen local excluido de Git; inicio rechazado sin configuración | 09; las claves externas se consumen y la ausencia impide iniciar | Aprobado |
| Credencial recuperable desde Git | Confundir eliminación actual con eliminación del historial | Detección con Gitleaks; procedimiento de revocación, investigación y corrección | 20; credencial sintética detectada en el primer commit después de retirarla del archivo actual | Aprobado |
| Intercepción o suplantación del transporte | Canal sin cifrado o certificado sin verificar | Servidor TLS 1.2 o superior; CA local; validación de nombre y cadena | 10 y 21; HTTPS real con CA e identidad verificadas, nombre incorrecto rechazado y canal autenticado en memoria | Aprobado |
| Exposición de datos mediante logs | Registrar formularios, URL completas o excepciones crudas | JSON con campos permitidos, identificadores internos y referencia de solicitud; rotación de archivos | 07, 11 y 13; sin contraseñas, correos, claves ni mensajes crudos de excepción | Aprobado |
| Acceso a expedientes ajenos | Autorizar solo por sesión sin comprobar propiedad | Verificación de rol y estudiante asociado en cada consulta | 12; expediente propio HTTP 200 y expediente ajeno HTTP 403 | Aprobado |
| Solicitudes cruzadas y abuso de sesión | Operaciones sin token y cookies débiles | CSRF, cookies Secure y HttpOnly, SameSite Lax, expiración y bloqueo temporal | 14, 15 y 16; CSRF ausente rechazado, HTTP y host ajeno rechazados y bloqueo tras cinco fallos | Aprobado |
| Operaciones sin trazabilidad | Continuar cuando falla el registro de seguridad | Rechazo de la operación con HTTP 503; transacciones revertidas y sesión sin autenticar | 19; fallo de escritura simulado sin revelar detalles internos | Aprobado |

La ejecución final aprobó los 21 casos, sin fallos, errores ni omisiones. La conexión HTTPS real se verificó después de que el responsable del equipo configurara una exclusión de inspección limitada a la dirección local. El navegador requiere su propia configuración de confianza para reconocer la CA del laboratorio.
