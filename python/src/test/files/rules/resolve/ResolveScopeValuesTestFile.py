from cryptography.hazmat.primitives.asymmetric import ec

# Test when two functions use the same local variable names
def func1():
    var1 = ec.SECP384R1()
    sk1 = ec.generate_private_key(var1) # Noncompliant {{SECP384R1}}
    return sk1
def func2():
    var1 = ec.BrainpoolP256R1()
    sk1 = ec.generate_private_key(var1) # Noncompliant {{BrainpoolP256R1}}
    return sk1

# Test when the parameter variable is being initialised again after it was used the first time
v1 = ec.SECP384R1()
private_key = ec.generate_private_key(v1) # Noncompliant {{SECP384R1}}
v1 = ec.BrainpoolP256R1()
# Below, the ideal result would only be {{BrainpoolP256R1}}, but because we cannot resolve control flow, we expect the following result:
private_key = ec.generate_private_key(v1) # Noncompliant {{BrainpoolP256R1}} {{SECP384R1}}