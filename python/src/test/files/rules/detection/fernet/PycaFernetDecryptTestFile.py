from cryptography.fernet import Fernet

def test1():
    key = Fernet.generate_key() # Noncompliant {{GENERATION}}

    def dec(ciphertext):
        f = Fernet(key)
        return f.decrypt(ciphertext)
    
def test2():
    key = Fernet.generate_key() # Noncompliant {{GENERATION}}

    def dec(ciphertext, time):
        f = Fernet(key)
        return f.decrypt_at_time(ciphertext, time)
