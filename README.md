# Semana 13

Ejercicio de privacidad y seguridad de datos de RR. HH. Los archivos con datos
de empleados, incluso los seudonimizados o cifrados, no se incluyen en este
repositorio.

## Requisitos

- Python 3.10 o posterior
- `cryptography` (`python -m pip install cryptography`)

Coloca localmente el CSV de entrada indicado en `config_seguridad.json` y define
las variables de entorno `CLAVE_HMAC`, `CLAVE_FERNET` y `API_TOKEN`. Luego ejecuta:

```powershell
python .\semana_13.py
```

La consulta a la API real está desactivada por defecto. Para habilitarla,
agrega `--api-real`.
