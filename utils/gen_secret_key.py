import secrets

def generate_secret_key(length=32):
    return secrets.token_hex(length)

if __name__ == '__main__':
    secret_key = generate_secret_key()
    print("Secret Key:", secret_key)
