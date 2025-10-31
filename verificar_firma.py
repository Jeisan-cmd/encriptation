from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# Cargar la clave pública
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read())

# Mensaje original
message = b"Mensaje para firmar"

# Firma a verificar
signature = bytes.fromhex("30539163bb7d5b8d7701f164c05d174f")  # Reemplaza con la firma real en formato hexadecimal

try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("La firma es válida.")
except:
    print("La firma no es válida.")
