from cryptography.hazmat.primitives import hashes

def create_hash(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    return digest.finalize().hex()

# Listas de mensajes
messages = [
    b"Mensaje 1",
    b"Mensaje 2",
    b"Mensaje 3"
]

# Crear hashes
hashes_values = {message: create_hash(message) for message in messages}

# Imprimir hashes
for message, hash_value in hashes_values.items():
    print(f"Hash de '{message.decode('utf-8')}': {hash_value}")

# Comparar hashes
message1 = b"Mensaje 1"
message2 = b"Mensaje 1"
hash1 = create_hash(message1)
hash2 = create_hash(message2)

if hash1 == hash2:
    print("Los hashes son iguales.")
else:
    print("Los hashes son diferentes.")
