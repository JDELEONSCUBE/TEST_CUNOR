# secure_app.py
# Versión corregida y endurecida del PoC. Sigue buenas prácticas.

import os
import sqlite3
import subprocess
import json
import base64
import requests
import hashlib
import secrets
import tempfile
import logging
import re
from pathlib import Path
from urllib.parse import urlparse
from ipaddress import ip_address, ip_network

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")

# Secretos: usar variables de entorno (no loggear)
DB_USER = os.getenv("APP_DB_USER", "")
DB_PASSWORD = os.getenv("APP_DB_PASSWORD", "")
API_KEY = os.getenv("APP_API_KEY", "")

# Directorio base permitido para lecturas (previene path traversal)
BASE_DIR = Path.cwd() / "data"
BASE_DIR.mkdir(exist_ok=True)


def init_db(db_path=":memory:"):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)")
    conn.commit()
    return conn


def db_lookup_user_safe(conn, username):
    # Consulta parametrizada para evitar SQLi
    sql = "SELECT id, username FROM users WHERE username = ?"
    cur = conn.cursor()
    return cur.execute(sql, (username,)).fetchall()


def run_ping_safe(host):
    # Validar el host (alfa-num, punto y guion) y usar lista de args sin shell
    if not re.fullmatch(r"[A-Za-z0-9\.\-]{1,253}", host):
        raise ValueError("Host inválido")
    # Nota: en Windows sería ["ping", "-n", "1", host]
    return subprocess.check_output(["ping", "-c", "1", host]).decode("utf-8", errors="ignore")


def read_file_safe(path_str):
    # Evitar path traversal verificando que el path resuelto quede bajo BASE_DIR
    target = (BASE_DIR / path_str).resolve()
    try:
        target.relative_to(BASE_DIR)
    except ValueError:
        raise PermissionError("Acceso denegado fuera del directorio permitido")
    return target.read_text(encoding="utf-8")


def safe_deserialize_json(b64_data):
    # Sustituir pickle por JSON (formato de datos, no objetos ejecutables)
    data = base64.b64decode(b64_data)
    return json.loads(data.decode("utf-8"))


_PRIVATE_NETS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]


def _is_private_ip(hostname):
    try:
        ip = ip_address(hostname)
        return any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def download_safe(url):
    # Validar esquema, hostname y bloquear SSRF a IPs privadas
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Esquema no permitido")
    host = parsed.hostname
    if not host or _is_private_ip(host):
        raise PermissionError("Destino no permitido")
    # Mantener verificación TLS y timeout
    resp = requests.get(url, timeout=5)  # verify=True por defecto
    resp.raise_for_status()
    return resp.text


def hash_password_strong(pw):
    # PBKDF2-HMAC con sal aleatoria
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 120_000)
    return base64.b64encode(salt + dk).decode("utf-8")


def write_temp_safe(content):
    # Usar NamedTemporaryFile / mkstemp con permisos seguros
    fd, name = tempfile.mkstemp(prefix="poc_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
    finally:
        # Nada más que cerrar; el archivo queda creado de forma segura
        pass
    return name


def parse_int_safe(value):
    try:
        return int(value)
    except ValueError:
        logging.warning("Valor no convertible a int")
        return None


def main():
    logging.info("== PoC seguro ==")

    conn = init_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                ("admin", hash_password_strong("admin123")))
    conn.commit()

    username = input("Usuario a buscar: ").strip()
    print("Resultados:", db_lookup_user_safe(conn, username))

    host = input("Host a ping (p.ej. 8.8.8.8): ").strip()
    try:
        print(run_ping_safe(host))
    except Exception as e:
        logging.error(f"Ping falló: {e}")

    path = input(f"Archivo bajo {BASE_DIR}/ : ").strip()
    try:
        print(read_file_safe(path)[:200])
    except Exception as e:
        logging.error(f"Lectura falló: {e}")

    b64 = input("Base64 de JSON seguro: ").strip()
    try:
        print("Datos JSON:", safe_deserialize_json(b64))
    except Exception as e:
        logging.error(f"JSON inválido: {e}")

    url = input("URL http(s) a descargar: ").strip()
    try:
        print(download_safe(url)[:200])
    except Exception as e:
        logging.error(f"Descarga falló: {e}")

    pw = input("Password para hash fuerte: ").strip()
    print("PBKDF2:", hash_password_strong(pw))

    temp_path = write_temp_safe("contenido temporal seguro")
    print("Escrito en:", temp_path)

    print("Parse int seguro:", parse_int_safe("no-es-int"))


if __name__ == "__main__":
    main()

