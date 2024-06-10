from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils

private_key = rsa.generate_private_key( # Noncompliant {{2048}}
    public_exponent=65537,
    key_size=2048,
)

message = b"A message I want to sign"
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    utils.Prehashed(hashes.SHA384())
)
# TODO: This example should also work when using variables to store hash values

# GROUND TRUTH (translation)
# 
# PrivateKey RSA
#   KeyLength 2048
#   Algorithm RSA
#       KeyGeneration KEYGENERATION
#       KeyLength 2048
#   Signature RSASSA-PSS
#       ProbabilisticSignatureScheme
#           MaskGenerationFunction MGF1
#               MessageDigest SHA256
#                   TODO: enrich*
#           (SaltLength ____)
#       MessageDigest SHA384
#           TODO: enrich*
#       Algorithm RSA
#           KeyLength 2048
#       Sign SIGN
# PublicKey RSA
#   KeyLength 2048
#   Algorithm RSA
#       KeyGeneration KEYGENERATION
#       KeyLength 2048
# 
# *: with BlockSize, DigestSize and KeyLength Children