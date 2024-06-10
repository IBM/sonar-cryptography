from imports.ResolveImportedStructImport import crypto_dict
from cryptography.hazmat.primitives.asymmetric import ec

private_key = ec.generate_private_key(crypto_dict['intermediate']) # Noncompliant {{BrainpoolP256R1}}