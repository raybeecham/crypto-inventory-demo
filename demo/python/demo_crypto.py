import hashlib
import hmac
import ssl

import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def demo() -> None:
    hashlib.md5(b"legacy")
    hashlib.sha256(b"modern")
    hashlib.new("sha1", b"legacy")
    hmac.new(b"key", b"payload", digestmod="sha256")
    rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ec.generate_private_key(ec.SECP256R1())
    Cipher(algorithms.AES(b"0" * 32), modes.GCM(b"1" * 12))
    ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    requests.get("https://example.com", verify=False, timeout=2)


if __name__ == "__main__":
    demo()
