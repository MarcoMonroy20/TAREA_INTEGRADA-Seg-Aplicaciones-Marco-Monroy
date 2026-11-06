# Índice de evidencias

Todos los registros, usuarios y credenciales de estas pruebas son ficticios. Las evidencias corresponden a ejecuciones reales del código del laboratorio.

| Archivo | Contenido verificable |
|---|---|
| `ejecucion_pruebas.txt` | Salida completa de unittest con 21 casos aprobados |
| `resultados_pruebas.json` | Resultado por caso y detalles de las comprobaciones |
| `gitleaks_historial.json` | Hallazgo del secreto sintético en el commit anterior; valor redactado |
| `gitleaks_salida.txt` | Salida de la herramienta durante el análisis del historial |
| `git_historial.txt` | Commits que introducen y retiran la credencial ficticia |
| `permisos_locales.json` | Permisos reales de carpeta y archivos privados, limitados al usuario actual y SYSTEM |
| `gitleaks_proyecto.json` | Análisis adicional del código y documentos preparados para la entrega |
| `capturas/01_ingreso.jpg` a `09_acceso_rechazado.jpg` | Nueve capturas originales del portal verificado en el navegador |
| `capturas_pruebas/01_sql.jpg` a `09_error.jpg` | Nueve capturas de resultados técnicos, una por cada prueba obligatoria |
| `visuales/index.html` | Visor de los resultados registrados, con enlaces a sus fuentes |

En `resultados_pruebas.json`, el detalle `sql` conserva la entrada utilizada y el número de filas antes y después de parametrizar. `xss` registra la codificación de salida; `passwords` contiene únicamente un hash de cuenta ficticia; `cifrado` muestra un paquete cifrado de ejemplo; `tls` identifica el protocolo, la suite y las verificaciones de certificado de una conexión real. `logging`, `login_fallido` y `errores` incluyen registros seguros de las pruebas.

Los casos 01 a 19 y 21 utilizan bases independientes de la del portal. El caso 20 genera un repositorio temporal y realiza el análisis real de su historial. Para reproducir los resultados ejecute `VERIFICAR_CONTROLES.cmd` después de preparar las dependencias.

Las capturas del navegador muestran ingreso, panel, directorio, búsqueda SQL controlada, comentario presentado como texto, reportes y permisos de consulta. El informe incorpora cuatro de ellas en sus anexos. Los resultados técnicos no dependen de que una pantalla se vea correcta.

Las capturas técnicas incluyen la fecha UTC de ejecución y la huella SHA-256 de su archivo fuente. Se obtuvieron abriendo el visor después de ejecutar las pruebas. El visor no sustituye el portal ni genera resultados de seguridad por sí mismo: muestra datos ya verificados en `resultados_pruebas.json`, el hallazgo de Gitleaks y los registros de las pruebas.
