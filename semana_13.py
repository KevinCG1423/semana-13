"""Ejercicio de privacidad y seguridad de datos de RR. HH.

Requiere: pip install cryptography

Las claves se leen del entorno. En PowerShell, antes de ejecutar:
  $env:CLAVE_HMAC = "una-clave-secreta-larga"
  $env:CLAVE_FERNET = (& python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
  $env:API_TOKEN = "token-de-prueba"
  python .\\semana_13.py

Para consultar la URL real definida en la configuración, agrega --api-real.
Por omisión se prueba el cliente API contra un servidor simulado.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from cryptography.fernet import Fernet, InvalidToken


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config_seguridad.json"
DATABASE_PATH = BASE_DIR / "empleados_rrhh.db"


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        config = json.load(file)
    if not isinstance(config, dict):
        raise ValueError("La configuración debe ser un objeto JSON.")
    return config


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Falta la variable de entorno obligatoria {name}.")
    return value


def pseudonymize_rut(rut: str, secret: bytes) -> str:
    canonical_rut = rut.strip().replace(".", "").replace("-", "").upper()
    if not canonical_rut:
        raise ValueError("Se encontró un RUT vacío.")
    return hmac.new(secret, canonical_rut.encode("utf-8"), hashlib.sha256).hexdigest()


def age_band(age: int, limits: list[int], labels: list[str]) -> str:
    if len(limits) != len(labels) + 1 or sorted(limits) != limits:
        raise ValueError("Los límites y etiquetas de edad de la configuración no coinciden.")
    index = bisect.bisect_right(limits, age) - 1
    if index < 0 or index >= len(labels):
        raise ValueError(f"Edad fuera de los límites configurados: {age}.")
    return labels[index]


def salary_band(salary: int, step: int) -> str:
    if step <= 0 or salary < 0:
        raise ValueError("El sueldo debe ser no negativo y el paso debe ser mayor que cero.")
    lower = (salary // step) * step
    upper = lower + step - 1
    return f"{lower}-{upper}"


def anonymize_csv(
    source: Path,
    destination: Path,
    anonymization: dict[str, Any],
    hmac_secret: bytes,
) -> None:
    with source.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        input_fields = reader.fieldnames
        if not input_fields:
            raise ValueError(f"El CSV no tiene encabezados: {source}")
        if len(set(input_fields)) != len(input_fields):
            raise ValueError("El CSV contiene encabezados duplicados.")

        rut_column = anonymization["columna_rut"]
        age_column = anonymization["columna_edad"]
        salary_column = anonymization["columna_sueldo"]
        required_fields = {rut_column, age_column, salary_column}
        missing = required_fields.difference(input_fields)
        if missing:
            raise ValueError(f"Faltan columnas requeridas en el CSV: {sorted(missing)}")

        suppressed = set(anonymization["columnas_suprimir"])
        output_fields = [
            anonymization["columna_pseudonimo"],
            "tramo_edad",
            "tramo_sueldo",
            *(field for field in input_fields if field not in suppressed),
        ]
        limits = anonymization["limites_edad"]
        labels = anonymization["etiquetas_edad"]
        salary_step = int(anonymization["paso_sueldo"])

        with destination.open("w", newline="", encoding="utf-8") as output_file:
            writer = csv.DictWriter(output_file, fieldnames=output_fields)
            writer.writeheader()
            for row_number, row in enumerate(reader, start=2):
                if None in row or any(value is None for value in row.values()):
                    raise ValueError(f"Fila CSV incompleta en la línea {row_number}.")
                try:
                    transformed = {
                        field: row[field]
                        for field in input_fields
                        if field not in suppressed
                    }
                    transformed[anonymization["columna_pseudonimo"]] = pseudonymize_rut(
                        row[rut_column], hmac_secret
                    )
                    transformed["tramo_edad"] = age_band(
                        int(row[age_column]), limits, labels
                    )
                    transformed["tramo_sueldo"] = salary_band(
                        int(row[salary_column]), salary_step
                    )
                except (KeyError, TypeError, ValueError) as error:
                    raise ValueError(
                        f"Datos inválidos en la línea {row_number}: {error}"
                    ) from error
                writer.writerow(transformed)


def quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def load_csv_into_sqlite(source: Path, database: Path, table: str) -> list[str]:
    with source.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        fields = reader.fieldnames
        if not fields or len(set(fields)) != len(fields):
            raise ValueError("El CSV requiere encabezados únicos para cargar en SQLite.")
        rows = list(reader)
    if not rows:
        raise ValueError("El CSV no contiene registros.")
    if any(None in row or any(value is None for value in row.values()) for row in rows):
        raise ValueError("El CSV contiene filas con cantidad de columnas incorrecta.")

    integer_fields = {
        field
        for field in fields
        if all(row[field].strip().lstrip("+-").isdigit() for row in rows)
    }
    definitions = ", ".join(
        f"{quote_identifier(field)} "
        f"{'INTEGER' if field in integer_fields else 'TEXT'}"
        for field in fields
    )
    placeholders = ", ".join("?" for _ in fields)
    insert_sql = (
        f"INSERT INTO {quote_identifier(table)} "
        f"({', '.join(quote_identifier(field) for field in fields)}) "
        f"VALUES ({placeholders})"
    )
    values = [
        tuple(int(row[field]) if field in integer_fields else row[field] for field in fields)
        for row in rows
    ]

    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database, isolation_level=None) as connection:
        connection.execute(f"DROP TABLE IF EXISTS {quote_identifier(table)}")
        connection.execute(
            f"CREATE TABLE {quote_identifier(table)} ({definitions})"
        )
        connection.executemany(insert_sql, values)
    return fields


WRITE_ACTIONS = {
    sqlite3.SQLITE_INSERT,
    sqlite3.SQLITE_UPDATE,
    sqlite3.SQLITE_DELETE,
}
READ_ACTIONS = {
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_FUNCTION,
    sqlite3.SQLITE_RECURSIVE,
}


def run_as_role(
    database: Path, table: str, role_config: dict[str, Any], query: str
) -> list[tuple[Any, ...]]:
    allowed_columns = role_config["columnas"]
    can_write = bool(role_config["escritura"])

    def authorize(
        action: int,
        arg1: str | None,
        arg2: str | None,
        database_name: str | None,
        source_name: str | None,
    ) -> int:
        del database_name, source_name
        if action in READ_ACTIONS:
            if action == sqlite3.SQLITE_READ:
                if arg1 != table:
                    return sqlite3.SQLITE_DENY
                if arg2 and allowed_columns != "*" and arg2 not in allowed_columns:
                    return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        if action in WRITE_ACTIONS:
            if not can_write or arg1 != table:
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_UPDATE and allowed_columns != "*":
                if arg2 not in allowed_columns:
                    return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    with sqlite3.connect(database, isolation_level=None) as connection:
        connection.set_authorizer(authorize)
        cursor = connection.execute(query)
        return cursor.fetchall()


def check_access_cases(
    database: Path, table: str, roles: dict[str, Any], cases: list[dict[str, str]]
) -> list[dict[str, Any]]:
    results = []
    for case in cases:
        try:
            run_as_role(database, table, roles[case["rol"]], case["sql"])
            actual = "OK"
        except sqlite3.DatabaseError:
            actual = "DENEGADO"
        results.append(
            {
                "rol": case["rol"],
                "sql": case["sql"],
                "esperado": case["esperado"],
                "obtenido": actual,
                "correcto": actual == case["esperado"],
            }
        )
    return results


def create_encrypted_transfer(
    csv_path: Path, encrypted_path: Path, manifest_path: Path, fernet: Fernet
) -> tuple[dict[str, Any], bytes]:
    encrypted_data = fernet.encrypt(csv_path.read_bytes())
    encrypted_path.write_bytes(encrypted_data)
    manifest = {
        "archivo": encrypted_path.name,
        "algoritmo": "SHA-256",
        "sha256": hashlib.sha256(encrypted_data).hexdigest(),
        "bytes": len(encrypted_data),
        "creado_utc": datetime.now(timezone.utc).isoformat(),
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest, encrypted_data


def verify_integrity(data: bytes, manifest: dict[str, Any]) -> bool:
    digest = hashlib.sha256(data).hexdigest()
    return hmac.compare_digest(digest, manifest["sha256"])


class SimulatedResponse:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self.status = status

    def __enter__(self) -> SimulatedResponse:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


OpenUrl = Callable[..., Any]
Sleep = Callable[[float], None]


def query_api(
    api_config: dict[str, Any],
    token: str,
    open_url: OpenUrl = urllib.request.urlopen,
    sleep: Sleep = time.sleep,
) -> dict[str, Any]:
    url = api_config["url"]
    if not isinstance(url, str) or not url.lower().startswith("https://"):
        raise ValueError("La API debe usar HTTPS.")
    attempts = int(api_config["intentos"])
    timeout = float(api_config["timeout"])
    base_wait = float(api_config["espera_base"])
    if attempts < 1 or timeout <= 0 or base_wait < 0:
        raise ValueError("Parámetros de reintento o timeout inválidos.")

    for attempt in range(attempts):
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with open_url(request, timeout=timeout) as response:
                status = response.status
                body = response.read()
            if status >= 500 or status == 429:
                raise urllib.error.HTTPError(
                    url, status, "Error temporal de API", None, None
                )
            if not 200 <= status < 300:
                raise RuntimeError(f"La API respondió con HTTP {status}.")
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("La API debe responder un objeto JSON.")
            return payload
        except urllib.error.HTTPError as error:
            should_retry = error.code >= 500 or error.code == 429
            if not should_retry or attempt + 1 == attempts:
                raise RuntimeError(
                    f"Error HTTP {error.code} al consultar la API."
                ) from error
        except (urllib.error.URLError, TimeoutError) as error:
            if attempt + 1 == attempts:
                raise RuntimeError(
                    f"La consulta a la API falló tras {attempts} intentos: {error}"
                ) from error
        sleep(base_wait * (2**attempt))
    raise RuntimeError("La consulta a la API finalizó sin respuesta.")


def test_api_with_simulated_server(
    api_config: dict[str, Any], token: str
) -> dict[str, Any]:
    calls = 0

    def simulated_server(request: urllib.request.Request, timeout: float) -> SimulatedResponse:
        nonlocal calls
        calls += 1
        auth = request.get_header("Authorization") or request.get_header("authorization")
        if not request.full_url.startswith("https://"):
            raise AssertionError("El cliente intentó consultar una URL sin HTTPS.")
        if auth != f"Bearer {token}":
            raise AssertionError("No se envió el token esperado en la cabecera.")
        if timeout != float(api_config["timeout"]):
            raise AssertionError("El cliente no usó el timeout configurado.")
        if calls < 3:
            raise urllib.error.HTTPError(
                request.full_url, 503, "Fallo temporal simulado", None, None
            )
        return SimulatedResponse(
            json.dumps({"estado": "ok", "simulado": True}).encode("utf-8")
        )

    response = query_api(api_config, token, simulated_server, sleep=lambda _: None)
    if calls != 3:
        raise AssertionError(f"Se esperaban 3 intentos; se observaron {calls}.")
    return {"correcto": True, "intentos_realizados": calls, "respuesta": response}


def main() -> int:
    parser = argparse.ArgumentParser(description="Ejercicio de seguridad RR. HH.")
    parser.add_argument(
        "--api-real",
        action="store_true",
        help="consulta la API HTTPS configurada en lugar de usar el servidor simulado",
    )
    args = parser.parse_args()

    try:
        config = load_config(CONFIG_PATH)
        hmac_secret = required_env(config["variables_entorno"]["clave_hmac"]).encode(
            "utf-8"
        )
        fernet = Fernet(
            required_env(config["variables_entorno"]["clave_fernet"]).encode("ascii")
        )
        api_token = required_env(config["variables_entorno"]["token_api"])

        input_csv = BASE_DIR / config["archivo_entrada"]
        anonymized_csv = BASE_DIR / config["archivo_anonimizado"]
        encrypted_csv = BASE_DIR / config["archivo_cifrado"]
        manifest_path = BASE_DIR / config["archivo_manifiesto"]
        report_path = BASE_DIR / config["archivo_informe"]

        anonymize_csv(input_csv, anonymized_csv, config["anonimizacion"], hmac_secret)
        table = config["tabla"]
        load_csv_into_sqlite(input_csv, DATABASE_PATH, table)
        access_results = check_access_cases(
            DATABASE_PATH, table, config["roles"], config["casos_prueba"]
        )
        if not all(result["correcto"] for result in access_results):
            raise RuntimeError("Uno o más casos de autorización no dieron el resultado esperado.")

        manifest, encrypted_data = create_encrypted_transfer(
            anonymized_csv, encrypted_csv, manifest_path, fernet
        )
        integrity_ok = verify_integrity(encrypted_data, manifest)
        if not integrity_ok:
            raise RuntimeError("Falló la verificación de integridad del archivo.")
        decrypted_data = fernet.decrypt(encrypted_data)
        if decrypted_data != anonymized_csv.read_bytes():
            raise RuntimeError("El contenido descifrado no coincide con el CSV anonimizado.")

        altered = bytearray(encrypted_data)
        altered[0] ^= 1
        altered_rejected = not verify_integrity(bytes(altered), manifest)
        if not altered_rejected:
            raise RuntimeError("La verificación no detectó la alteración simulada.")
        try:
            fernet.decrypt(bytes(altered))
            altered_decryption_rejected = False
        except InvalidToken:
            altered_decryption_rejected = True
        if not altered_decryption_rejected:
            raise RuntimeError("Fernet aceptó el archivo alterado.")

        if args.api_real:
            api_result = {
                "modo": "real",
                "respuesta": query_api(config["api"], api_token),
            }
        else:
            api_result = {
                "modo": "simulado",
                **test_api_with_simulated_server(config["api"], api_token),
            }

        report = {
            "casos_acceso": access_results,
            "transferencia": {
                "integridad_original": integrity_ok,
                "integridad_alteracion_rechazada": altered_rejected,
                "descifrado_original_correcto": True,
                "descifrado_alteracion_rechazado": altered_decryption_rejected,
                "manifiesto": manifest,
            },
            "api": api_result,
            "respuesta": (
                "El resultado es seudonimizado, no anónimo: el HMAC permite "
                "vincular registros de forma estable para quien controle la clave, "
                "y los cuasi-identificadores pueden facilitar reidentificación."
            ),
        }
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"CSV seudonimizado: {anonymized_csv}")
        print(f"Base SQLite: {DATABASE_PATH}")
        print(f"CSV cifrado: {encrypted_csv}")
        print(f"Manifiesto SHA-256: {manifest_path}")
        print(f"Informe: {report_path}")
        print(f"Casos de acceso correctos: {len(access_results)}/{len(access_results)}")
        print(f"Integridad y alteración simulada: OK")
        print(f"API ({api_result['modo']}): OK")
        print(report["respuesta"])
        return 0
    except (OSError, KeyError, TypeError, ValueError, RuntimeError, sqlite3.Error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
