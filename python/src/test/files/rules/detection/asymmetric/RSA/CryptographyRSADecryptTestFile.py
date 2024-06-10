from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

private_key = rsa.generate_private_key( # Noncompliant {{1024}}
    public_exponent=65537,
    key_size=1024,
)

def decrypt(ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# GROUND TRUTH (translation)
# 
# PrivateKey RSA
#   KeyLength 1024
#   Algorithm RSA
#       KeyLength 1024
#       KeyGeneration KEYGENERATION
#       OptimalAsymmetricEncryptionPadding OAEP
#           MaskGenerationFunction MGF1
#               MessageDigest SHA256
#           MessageDigest SHA256
#       Decrypt DECRYPT
# PublicKey RSA
#   KeyLength 1024
#   Algorithm RSA
#       KeyLength 1024
#       KeyGeneration KEYGENERATION
#       OptimalAsymmetricEncryptionPadding OAEP
#           MaskGenerationFunction MGF1
#               MessageDigest SHA256
#           MessageDigest SHA256
#       Decrypt DECRYPT