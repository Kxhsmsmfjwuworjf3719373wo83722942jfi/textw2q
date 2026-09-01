import secrets
import hashlib
import hmac
import ipaddress
from datetime import datetime


class Enterbershier:
    def __init__(self):
        self.api_name = "Enterbershier"
        self.version = "VIPV9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999"
        self.api_key = "EBH_" + secrets.token_hex(32)
        self.secret_key = secrets.token_bytes(32)
        self.whitelist_ip = []
        self.allowed_ports = []
        self.status = "ACTIVE"
        self.created = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def add_ip(self, ip):
        ipaddress.ip_address(ip)
        self.whitelist_ip.append(ip)

    def add_port(self, port):
        if 1 <= int(port) <= 65535:
            self.allowed_ports.append(int(port))
        else:
            raise ValueError("Port tidak valid")

    def check_ip(self, ip):
        return ip in self.whitelist_ip

    def check_port(self, port):
        return int(port) in self.allowed_ports

    def create_token(self, message):
        return hmac.new(
            self.secret_key,
            message.encode(),
            hashlib.sha256
        ).hexdigest()

    def verify_token(self, message, token):
        valid = self.create_token(message)
        return hmac.compare_digest(valid, token)

    def hash_data(self, text):
        return hashlib.sha256(text.encode()).hexdigest()

    def info(self):
        return {
            "api": self.api_name,
            "version": self.version,
            "status": self.status,
            "created": self.created,
            "api_key": self.api_key,
            "whitelist_ip": self.whitelist_ip,
            "allowed_ports": self.allowed_ports
        }


if __name__ == "__main__":
    api = Enterbershier()

    api.add_ip("192.168.1.10")
    api.add_port(443)

    token = api.create_token("ENTERBERSHIER")

    print(api.info())
    print("Token :", token)
    print("IP Valid :", api.check_ip("192.168.1.10"))
    print("Port Valid :", api.check_port(443))
    print("Hash :", api.hash_data("Hello World"))