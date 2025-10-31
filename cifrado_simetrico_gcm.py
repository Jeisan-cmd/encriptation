from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generar clave y vector de inicialización
key = os.urandom(32)  # Clave de 256 bits
iv = os.urandom(12)   # Vector de inicialización de 96 bits para GCM

# Texto a cifrar
plaintext = "Mensaje para cifrado simétrico".encode('utf-8')
cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
encryptor = cipher.encryptor()

# Cifrar el texto
ciphertext = encryptor.update(plaintext) + encryptor.finalize()
print("Texto cifrado:", ciphertext)
print("Tag:", encryptor.tag.hex())

# Descifrar el texto
decryptor = cipher.decryptor()
decryptor.authenticate_additional_data(b'')  # Pasa una cadena de bytes vacía si no hay datos adicionales
decrypted = decryptor.update(ciphertext) + decryptor.finalize()
print("Texto descifrado:", decrypted.decode('utf-8'))
