#!/usr/bin/env python3
"""
BillScan PRO — Serveur HTTPS local
Lance un serveur HTTPS avec certificat auto-signé
pour permettre l'accès à la caméra via getUserMedia.

Usage:
  python server.py

Puis ouvre: https://localhost:8443
"""

import http.server
import ssl
import os
import sys
import socket
import subprocess
import tempfile

PORT = 8443
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

# ── Couleurs terminal ──
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner():
    print(f"""
{GREEN}{BOLD}
╔══════════════════════════════════════════╗
║       BILLSCAN PRO — Serveur HTTPS       ║
║     Détecteur de Faux Billets Local      ║
╚══════════════════════════════════════════╝
{RESET}""")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def generate_cert():
    """Génère un certificat SSL auto-signé avec openssl."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        print(f"{CYAN}► Certificat SSL existant trouvé.{RESET}")
        return True

    print(f"{YELLOW}► Génération du certificat SSL auto-signé...{RESET}")

    # Méthode 1 : openssl
    try:
        local_ip = get_local_ip()
        subj = f"/CN=localhost/O=BillScan/C=CI"
        san = f"subjectAltName=IP:127.0.0.1,IP:{local_ip},DNS:localhost"

        # Fichier config SAN
        cfg = f"""[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no
[req_distinguished_name]
CN=localhost
[v3_req]
subjectAltName=IP:127.0.0.1,IP:{local_ip},DNS:localhost
"""
        with open("ssl.cfg", "w") as f:
            f.write(cfg)

        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", KEY_FILE, "-out", CERT_FILE,
            "-days", "365", "-nodes",
            "-config", "ssl.cfg"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if os.path.exists(CERT_FILE):
            os.remove("ssl.cfg")
            print(f"{GREEN}✓ Certificat SSL généré avec openssl.{RESET}")
            return True
    except FileNotFoundError:
        pass

    # Méthode 2 : Python cryptography
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime, ipaddress

        print(f"{YELLOW}► Utilisation de la lib Python 'cryptography'...{RESET}")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        local_ip = get_local_ip()
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"localhost")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.IPAddress(ipaddress.IPv4Address(u"127.0.0.1")),
                x509.IPAddress(ipaddress.IPv4Address(local_ip)),
            ]), critical=False)
            .sign(key, hashes.SHA256())
        )
        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"{GREEN}✓ Certificat SSL généré avec Python cryptography.{RESET}")
        return True
    except ImportError:
        pass

    # Méthode 3 : certificat auto-signé minimal (pyOpenSSL)
    try:
        import OpenSSL.crypto as crypto
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().CN = "localhost"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha256')
        with open(CERT_FILE, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(KEY_FILE, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
        print(f"{GREEN}✓ Certificat SSL généré avec pyOpenSSL.{RESET}")
        return True
    except ImportError:
        pass

    return False

class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        status = args[1] if len(args) > 1 else "?"
        color = GREEN if str(status).startswith("2") else YELLOW if str(status).startswith("3") else RED
        print(f"  {color}[{self.log_date_time_string()}] {format % args}{RESET}")

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Cache-Control", "no-cache")
        super().end_headers()

def main():
    banner()

    # Vérifier que BillScan_PRO.html existe
    html_file = "BillScan_PRO.html"
    if not os.path.exists(html_file):
        # Chercher dans le répertoire courant
        files = [f for f in os.listdir('.') if f.endswith('.html')]
        if files:
            print(f"{YELLOW}⚠ '{html_file}' non trouvé. Fichiers HTML disponibles : {files}{RESET}")
            print(f"{CYAN}► Place 'BillScan_PRO.html' dans le même dossier que ce script.{RESET}")
        else:
            print(f"{RED}✗ Aucun fichier HTML trouvé dans ce dossier !{RESET}")
            print(f"{CYAN}► Place 'BillScan_PRO.html' ici : {os.getcwd()}{RESET}")
        print()

    # Générer certificat
    cert_ok = generate_cert()

    if not cert_ok:
        print(f"""
{RED}✗ Impossible de générer un certificat SSL automatiquement.{RESET}
{YELLOW}
Solutions :
1. Installe openssl : https://slproweb.com/products/Win32OpenSSL.html (Windows)
   ou : brew install openssl (Mac)
   ou : sudo apt install openssl (Linux)

2. Ou installe la lib Python :
   pip install cryptography
   puis relance : python server.py
{RESET}"")
        sys.exit(1)

    # Lancer le serveur
    local_ip = get_local_ip()
    os.chdir(os.path.dirname(os.path.abspath(__file__)) or '.')

    try:
        httpd = http.server.HTTPServer(('0.0.0.0', PORT), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT_FILE, KEY_FILE)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

        print(f"""
{GREEN}{BOLD}✓ Serveur HTTPS démarré !{RESET}

{CYAN}Ouvre dans ton navigateur :{RESET}

  {BOLD}https://localhost:{PORT}/BillScan_PRO.html{RESET}
  {BOLD}https://{local_ip}:{PORT}/BillScan_PRO.html{RESET}  ← depuis un autre appareil

{YELLOW}⚠ Avertissement SSL normal :{RESET}
  Le navigateur va afficher "Votre connexion n'est pas privée"
  → Clique {BOLD}Avancé{RESET} → {BOLD}Continuer vers localhost{RESET}
  C'est normal pour un certificat auto-signé local.

{CYAN}► La caméra fonctionnera après avoir accepté.{RESET}

{GREEN}En attente de connexions... (Ctrl+C pour arrêter){RESET}
""")
        httpd.serve_forever()

    except KeyboardInterrupt:
        print(f"\n{YELLOW}► Serveur arrêté.{RESET}")
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"{RED}✗ Port {PORT} déjà utilisé. Change PORT = {PORT} en haut du script.{RESET}")
        else:
            raise

if __name__ == "__main__":
    main()