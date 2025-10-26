from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64

# Base64 encoded modulus from your public key data
modulus_base64 = "8a36CUlB-4L90WsTmQ_nGceghdZl4N8gwhTMQdh7Z_F046_slxU73kN88ri66jbc1aMj0lKd2wo4DlF7QNNN291b5OTP-FwnRB0E_Bs7Zq_TvBYLSYgU8dzDKlvO8xFg1juXtWe3E6CijwnNdTxD9bgoLxiQyDIW66BX_oFtPs0SsaGRWJpMiCSUex_Oob_DsF8uSEwqvqWibnKh-mFztryth3krI6pIDG4ircip9jktmd_sNg9i6a_gWAIEqDu-DJfK6EahVICrDXVFxA4GyW-3AfCI6AdeerSs9ClAFDfSvQa7jjZsYIqRaheqiRZtU1qnny-k8xsWe0DDV6tFSQ"
modulus_bytes = base64.urlsafe_b64decode(modulus_base64 + '==')  # Decode base64
modulus = int.from_bytes(modulus_bytes, byteorder='big')

# Public exponent
exponent = 65537

# Create RSA public key
public_numbers = rsa.RSAPublicNumbers(exponent, modulus)
public_key = public_numbers.public_key(backend=default_backend())

# Data to encrypt
data = "1745"

# Encrypt the data using PKCS1v1.5 padding
ciphertext = public_key.encrypt(
    data.encode(),
    padding.PKCS1v15()  # Matches RSAES-PKCS1-V1_5 padding
)

# Encode the encrypted data in base64
encrypted_pin_base64 = base64.b64encode(ciphertext).decode('utf-8')
print("Encrypted PIN (base64):", encrypted_pin_base64)
