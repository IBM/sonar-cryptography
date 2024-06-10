from cryptography.hazmat.primitives.asymmetric import ec

crypto_dict = {'beginner': ec.SECP384R1(),
               'intermediate': ec.BrainpoolP256R1(),
               'advanced': ec.SECT233K1()}
