from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Generate a private key for use in the exchange.
server_private_key = ec.generate_private_key( # Noncompliant {{SECP384R1}}
    ec.SECP384R1()
)

def exchange(public_key):
    shared_key = server_private_key.exchange(
        ec.ECDH(), public_key)
    
    # Perform key derivation. // TODO: How should this key derivation be linked to the private key?
    # derived_key = HKDF(
    #     algorithm=hashes.SHA256(),
    #     length=32,
    #     salt=None,
    #     info=b'handshake data',
    # ).derive(shared_key)
    # return derived_key

# GROUND TRUTH (translation)
# 
# PrivateKey EC
#   Protocol ECDH                       // TODO: add Protocol to the model
#       KeyDerivationFunction SHA-256   // TODO: add KeyDerivationFunction to the model
#   EllipticCurveAlgorithm EC
#       EllipticCurve SECP384R1
#       KeyGeneration KEYGENERATION
# PublicKey EC
#     EllipticCurveAlgorithm EC
#         EllipticCurve SECP384R1
#         KeyGeneration KEYGENERATION
