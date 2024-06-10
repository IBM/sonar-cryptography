from cryptography.hazmat.primitives.asymmetric import ec

l1 = [ec.SECP384R1(), ec.BrainpoolP256R1(), ec.SECP192R1()]
for curve in l1:
    ec.generate_private_key(curve) # Noncompliant {{SECP384R1}} {{BrainpoolP256R1}} {{SECP192R1}}

i = 0
while i < len(l1):
    ec.generate_private_key(l1[i]) # Noncompliant {{SECP384R1}} {{BrainpoolP256R1}} {{SECP192R1}}
    i += 1