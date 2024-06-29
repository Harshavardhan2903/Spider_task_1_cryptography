from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate public key
    public_key = private_key.public_key()

    # Save the private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save the public key
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Keys generated and saved.")

generate_keys()


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def sign_file(file_path, private_key_path):
    # Load the private key from file
    with open(private_key_path, "rb") as key_file:
        private_key = load_pem_private_key(key_file.read(), password=None, backend=default_backend())

    # Read the content of the file
    with open(file_path, "rb") as f:
        data = f.read()

    # Sign the data
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Save the signature to a file
    with open(file_path + ".sig", "wb") as sig_file:
        sig_file.write(signature)

    print("File signed.")

# Example use:
sign_file("example.txt", "private_key.pem")

from cryptography.hazmat.primitives.serialization import load_pem_public_key

def verify_signature(file_path, signature_path, public_key_path):
    # Load the public key
    with open(public_key_path, "rb") as key_file:
        public_key = load_pem_public_key(key_file.read(), backend=default_backend())

    # Load the signature
    with open(signature_path, "rb") as sig_file:
        signature = sig_file.read()

    # Load the file data
    with open(file_path, "rb") as f:
        data = f.read()

    try:
        # Attempt to verify the signature
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
    except Exception as e:
        print("Signature is invalid. Error:", str(e))

# Example use:
verify_signature("example.txt", "example.txt.sig", "public_key.pem")

