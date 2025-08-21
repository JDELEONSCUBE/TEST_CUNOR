# insecure_app.py
# Archivo INTENCIONALMENTE vulnerable para PoC con SonarCloud.
# NO usar en producción.

import os
import sqlite3
import subprocess
import pickle  # VULN: deserialización insegura
import base64
import requests  # VULN: verify=False
import hashlib  # VULN: MD5
import tempfile  # VULN: mktemp
import logging
from pathlib import Path

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s:%(message)s")

# VULN: Secretos en duro / credenciales hardcodeadas
DB_USER = "admin"
DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk_live_1234567890abcdef"  # VULN: secreto expuesto


def init_db(db_path=":memory:"):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT)")
    conn.commit()
    return conn


def db_lookup_user_vuln(conn, username):
    # VULN: SQL Injection por concatenación de strings
    sql = f"SELECT id, username FROM users WHERE username = '{username}'"
    logging.debug(f"Ejecutando SQL: {sql}")  # VULN: logging de consulta cruda
    cur = conn.cursor()
    return cur.execute(sql).fetchall()


def run_ping_vuln(host):
    # VULN: Command Injection por shell=True
    cmd = f"ping -c 1 {host}"
    logging.debug(f"Ejecutando comando: {cmd}")
    return subprocess.check_output(cmd, shell=True).decode("utf-8", errors="ignore")


def read_file_vuln(path_str):
    # VULN: Path traversal sin validación
    path = Path(path_str)
    return path.read_text(encoding="utf-8")


def unsafe_deserialize(b64_data):
    # VULN: Deserialización insegura con pickle
    data = base64.b64decode(b64_data)
    return pickle.loads(data)


def download_vuln(url):
    # VULN: verify=False (SSL deshabilitada) + posible SSRF
    requests.packages.urllib3.disable_warnings()  # VULN: ocultar advertencias
    resp = requests.get(url, verify=False, timeout=2)
    return resp.text


def hash_password_vuln(pw):
    # VULN: Hash criptográficamente débil
    return hashlib.md5(pw.encode("utf-8")).hexdigest()


def write_temp_vuln(content):
    # VULN: tempfile.mktemp es inseguro (TOCTOU)
    name = tempfile.mktemp(prefix="poc_", suffix=".txt")
    with open(name, "w", encoding="utf-8") as f:
        f.write(content)
    return name


def ignore_exceptions_vuln(value):
    # VULN: captura demasiado amplia y silenciosa
    try:
        return int(value)
    except Exception:
        return None


def log_sensitive_vuln(pw):
    # VULN: registro de información sensible
    logging.debug(f"User password is: {pw}")


def main():
    logging.info("== PoC vulnerable ==")
    # VULN: uso de secretos en logs
    logging.debug(f"Conectando con {DB_USER}/{DB_PASSWORD}, API_KEY={API_KEY}")

    conn = init_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (username, password_hash) VALUES ('admin', ?)", (hash_password_vuln("admin123"),))
    conn.commit()

    username = input("Usuario a buscar (prueba con: admin' OR '1'='1): ")
    print("Resultados:", db_lookup_user_vuln(conn, username))

    host = input("Host a ping (p.ej. 8.8.8.8; prueba con `8.8.8.8; ls`): ")
    print(run_ping_vuln(host))

    path = input("Ruta de archivo a leer (p.ej. ../../etc/passwd): ")
    try:
        print(read_file_vuln(path)[:200])
    except Exception as e:
        logging.error(f"Error leyendo archivo: {e}")

    b64 = input("Base64 de objeto pickle (peligroso): ")
    try:
        print("Objeto deserializado:", unsafe_deserialize(b64))
    except Exception as e:
        logging.error(f"Error en pickle: {e}")

    url = input("URL a descargar (p.ej. https://example.com): ")
    try:
        print(download_vuln(url)[:200])
    except Exception as e:
        logging.error(f"Error descargando: {e}")

    pw = input("Password para hash débil: ")
    log_sensitive_vuln(pw)
    print("MD5:", hash_password_vuln(pw))

    temp_path = write_temp_vuln("contenido temporal")
    print("Escrito en:", temp_path)

    print("Parse int inseguro:", ignore_exceptions_vuln("no-es-int"))


if __name__ == "__main__":
    main()
