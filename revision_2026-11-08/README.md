# Evidencia de la revisión del 8 de noviembre de 2026

La revisión se realizó en Windows con datos ficticios sobre el código de la revisión `20d238cc506298eacacf08ea888b319776bf272d`. La suite ejecutó 21 casos, sin fallos, errores ni omisiones. Las comprobaciones adicionales corresponden a las salidas incluidas en el informe revisado.

| Archivo | Contenido |
|---|---|
| [resultados_demostracion.json](resultados_demostracion.json) | Entradas y resultados de SQL, XSS, comandos, SQLite, rotación de clave, HTTPS en el puerto 8443 y registros. |
| [ejecucion_pruebas.txt](ejecucion_pruebas.txt) | Salida de los 21 casos de `pruebas.py`. |
| [gitleaks_historial.json](gitleaks_historial.json) | Hallazgo en el repositorio ficticio con el valor redactado. |
| [verificar_demostracion.py](verificar_demostracion.py) | Repite la suite y las comprobaciones adicionales en una copia temporal. |

## Reproducción

1. En la raíz del repositorio, prepara Python y las dependencias como indica el README principal. Instala Gitleaks con `instalar_gitleaks.ps1`. La comparación de XSS en el navegador utiliza Microsoft Edge en Windows.
2. Detén el portal si está abierto. La prueba complementaria usa el puerto local 8443 y la suite utiliza el 8444.
3. Desde PowerShell, ejecuta el siguiente comando en la raíz del proyecto.

```powershell
.\.venv\Scripts\python.exe .\revision_2026-11-08\verificar_demostracion.py --salida resultados_revision_local.json
```

El script copia el código y las plantillas a una carpeta temporal y genera sus propios datos y certificados de laboratorio. La verificación HTTPS carga la CA temporal y comprueba la identidad. La rotación de clave recifra dos expedientes ficticios en una base desechable. El JSON de una ejecución posterior tendrá fechas e identificadores nuevos.

La salida esperada indica 21 pruebas sin fallos, errores ni omisiones, TLS 1.2 y 1.3 con HTTP 200 en el puerto 8443 y rechazo de un nombre incorrecto. El proceso devuelve un código distinto de cero si una comprobación requerida queda pendiente o falla. En ese caso, revisa el motivo indicado en el JSON o en la consola.
