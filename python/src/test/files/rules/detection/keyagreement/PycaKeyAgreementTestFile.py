from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey

# Generate a private key for use in the exchange.
private_key = X25519PrivateKey.generate() # Noncompliant {{(KeyAgreement) x25519}}
# In a real handshake the peer_public_key will be received from the
# other party. For this example we'll generate another private key and
# get a public key from that. Note that in a DH handshake both peers
# must agree on a common set of parameters.
peer_public_key = X25519PrivateKey.generate().public_key() # Noncompliant {{(KeyAgreement) x25519}}
shared_key = private_key.exchange(peer_public_key)

# Generate a private key for use in the exchange.
private_key = X448PrivateKey.generate() # Noncompliant {{(KeyAgreement) x448}}
# In a real handshake the peer_public_key will be received from the
# other party. For this example we'll generate another private key and
# get a public key from that. Note that in a DH handshake both peers
# must agree on a common set of parameters.
peer_public_key = X448PrivateKey.generate().public_key() # Noncompliant {{(KeyAgreement) x448}}
shared_key = private_key.exchange(peer_public_key)