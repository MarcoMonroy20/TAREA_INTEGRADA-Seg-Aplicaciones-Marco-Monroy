# Portal universitario de laboratorio

Proyecto individual de Seguridad en Aplicaciones, semanas 4 y 5. Implementa registro e inicio de sesión, expedientes, búsqueda, comentarios y reportes con información ficticia.

## Inicio en Windows

1. Abra la carpeta del proyecto. Necesita Python 3.12 o posterior y Git. La instalación inicial de bibliotecas requiere conexión a Internet.
2. Ejecute `INICIAR_LABORATORIO.cmd`. El iniciador prepara un entorno de Python, instala las tres bibliotecas de `requirements.txt`, genera claves y certificados locales y restringe los permisos de `datos_locales` al usuario actual y SYSTEM.
3. Abra `https://127.0.0.1:8443`.
4. Consulte `datos_locales/accesos.txt`. Contiene las cuentas ficticias de administrador y estudiantes y una contraseña inicial generada para ese equipo.
5. Mantenga abierta la ventana del servidor. Para detenerlo, presione Ctrl+C.

La preparación conserva los datos de ejecuciones anteriores. Si detecta archivos incompletos, informa el problema y evita sobrescribir claves o bases de datos. No elimine la clave AES de una base existente: perdería la posibilidad de recuperar sus expedientes.

## Certificado y estado de HTTPS

El servidor utiliza una CA local de laboratorio y un certificado válido para `localhost` y `127.0.0.1`. La CA no es pública. El navegador necesita una configuración de confianza específica para el laboratorio; no se instala ninguna raíz de confianza de forma automática. La clave privada de la CA se descarta tras emitir el certificado. El certificado del servidor vence a los siete días.

En el equipo de verificación, Norton interceptó inicialmente las conexiones locales y presentó un certificado con emisor `Norton Web/Mail Shield Untrusted Root`, distinto del certificado del laboratorio. La prueba rechazó esa cadena. El responsable del equipo agregó una exclusión limitada a `https://127.0.0.1`. Después se aprobó la conexión HTTPS real con validación de CA e identidad y rechazo de un nombre incorrecto. No se desactivó la validación del certificado.

El caso 10 usa el puerto local 8444. El servidor del portal usa 8443. El navegador sigue necesitando reconocer la CA local para mostrar una conexión de confianza; la verificación automática la carga expresamente y no modifica el almacén de certificados de Windows. Si el navegador muestra una advertencia, la revisión de confianza corresponde al responsable del equipo. La prueba no implica que todos los navegadores confíen automáticamente en esta CA. Retire la excepción de Norton después del laboratorio. No se necesita publicar el portal en Internet.

## Verificación

Ejecute `VERIFICAR_CONTROLES.cmd` o, con el entorno activado:

```powershell
python pruebas.py
```

La prueba de Git utiliza Gitleaks 8.30.1. Los ejecutables descargados se excluyen del repositorio. Ejecute `instalar_gitleaks.ps1` para obtener la versión oficial de Windows de 64 bits; el instalador comprueba el SHA-256 del archivo descargado. En otros sistemas defina `GITLEAKS_BIN` con la ruta del ejecutable correspondiente.

Los resultados se guardan en `evidencias/resultados_pruebas.json`, `ejecucion_pruebas.txt`, `gitleaks_historial.json`, `gitleaks_salida.txt` y `git_historial.txt`. Las pantallas del portal están en `evidencias/capturas`; las nueve capturas técnicas de las pruebas obligatorias están en `evidencias/capturas_pruebas`. Abra `VER_EVIDENCIAS.cmd` para consultar el visor con la entrada, el resultado y la fuente de cada verificación. Después de repetir las pruebas, ejecute `python evidencias_visuales.py` para actualizar ese visor. El código de salida es 0 cuando todas las pruebas se completan, 1 si hay fallos y 2 si quedan comprobaciones pendientes. Las pruebas utilizan bases temporales independientes de la base del portal.

## Archivos principales

| Archivo | Función |
|---|---|
| `app.py` | Rutas, consultas parametrizadas, autorización, registros y reportes |
| `seguridad.py` | Validación, Argon2id y AES-256-GCM |
| `preparar.py` | Configuración y certificados ficticios del equipo |
| `ejecutar.py` | Servidor HTTPS limitado a 127.0.0.1:8443 |
| `pruebas.py` | Pruebas técnicas y generación de evidencias reales |
| `documentacion/Informe_tecnico.docx` | Análisis, implementación, resultados y defensa |
| `documentacion/Matriz_seguridad.md` | Riesgo, causa, control y verificación |
| `documentacion/Guia_demostracion.md` | Secuencia práctica y preguntas de defensa |
| `evidencias_visuales.py` | Genera el visor a partir de los resultados reales registrados |
| `documentacion/Entrega_repositorio.md` | Lista de archivos y pasos para entregar en GitHub |

## Alcance y permisos

El administrador puede buscar estudiantes, consultar o modificar expedientes y generar reportes. El estudiante consulta únicamente su expediente; ambos roles publican comentarios. Los registros académicos sensibles se cifran por expediente. Nombres, identificadores y correos permanecen como metadatos de la aplicación: no se afirma que toda la base esté cifrada.

Las claves de sesión y de cifrado se generan fuera del código. `ejecutar.py` carga el archivo local y las entrega como variables de entorno; `app.py` las consume y rechaza el inicio cuando faltan. Las contraseñas no se cifran de forma reversible: se conservan como hashes Argon2id con sal.

No ejecute el servidor como administrador. Use una cuenta local sin privilegios de instalación o administración del sistema para la demostración. Los reportes descargados contienen calificaciones en claro y deben conservarse bajo el control del responsable del laboratorio.

## Rotación y revocación

Una credencial expuesta debe revocarse en el servicio que la reconoce, investigarse y sustituirse. Borrar una línea de Git no invalida una credencial ni elimina sus versiones anteriores. La prueba utiliza una regla propia de Gitleaks para una credencial sintética; detectarla no equivale a verificar su validez en un proveedor externo.

Para rotar la clave de sesión, genere otro valor aleatorio, actualice la fuente externa y reinicie el proceso. Las sesiones anteriores dejarán de validar. Para rotar AES, haga una copia protegida de la base y la clave vigente; descifre cada expediente con la clave anterior y vuelva a cifrarlo con una nueva clave y un nonce nuevo. Verifique todas las lecturas antes de retirar la clave anterior. Este procedimiento se documenta, pero no se automatiza en el laboratorio.

## Límite de uso

El servidor de Werkzeug se utiliza exclusivamente para el laboratorio local; no es una instalación de producción. No incorpora correo de recuperación, MFA, protección distribuida contra abuso ni una bóveda empresarial. El límite de búsqueda es de 100 filas y el de comentarios visibles es de 50. Todos los datos son ficticios.
