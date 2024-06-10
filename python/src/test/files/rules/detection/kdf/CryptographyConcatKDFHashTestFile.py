import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

otherinfo = b"concatkdf-example"

ckdf = ConcatKDFHash( # Noncompliant {{KDF}} {{SHA256}} {{32}}
    algorithm=hashes.SHA256(),
    length=32,
    otherinfo=otherinfo,
)

key = ckdf.derive(b"input key")