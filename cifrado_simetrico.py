from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generar clave y vector de inicialización
key = os.urandom(32)  # Clave de 256 bits
iv = os.urandom(16)   # Vector de inicialización

# Texto a cifrar
plaintext = "Mensaje para cifrado simétrico".encode('utf-8')
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()

# Añadir padding manual
pad = 16 - len(plaintext) % 16
padded_plaintext = plaintext + bytes([pad] * pad)
ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
print("Texto cifrado:", ciphertext)

# Descifrar el texto
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
decrypted = decrypted_padded[:-decrypted_padded[-1]]
print("Texto descifrado:", decrypted.decode('utf-8'))
