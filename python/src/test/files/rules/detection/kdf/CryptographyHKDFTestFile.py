import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

salt = os.urandom(16)
info = b"hkdf-example"

hkdf = HKDF( # Noncompliant {{KDF}} {{SHA256}} {{32}}
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    info=info,
)

key = hkdf.derive(b"input key")