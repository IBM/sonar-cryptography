import cryptography.hazmat.primitives.asymmetric.ec as asym_crypto

curve = asym_crypto.SECP384R1()
private_key = asym_crypto.generate_private_key(curve) # Noncompliant {{SECP384R1}}