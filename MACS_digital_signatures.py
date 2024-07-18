from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

def generate_mac(symmetric_key, nonce, plaintext):
    """
    Generates a MAC (Message Authentication Code) using AES-GCM encryption.

    :param symmetric_key: The symmetric key used for encryption.
    :param nonce: The nonce value for AES-GCM.
    :param plaintext: The plaintext message to be authenticated.
    :return: The MAC as bytes.
    """
    symmetric_cipher = AES.new(symmetric_key, AES.MODE_GCM, nonce=nonce)
    mac, _ = symmetric_cipher.encrypt_and_digest(plaintext)
    return mac

def generate_hmac(symmetric_key, nonce, plaintext):
    """
    Generates an HMAC (Hash-based Message Authentication Code) with AES-GCM encryption.

    :param symmetric_key: The symmetric key used for encryption and HMAC.
    :param nonce: The nonce value for AES-GCM.
    :param plaintext: The plaintext message to be authenticated.
    :return: The ciphertext with HMAC as bytes.
    """
    hmac_object = HMAC.new(symmetric_key, digestmod=SHA256)
    hmac_object.update(plaintext)
    hmac_digest = hmac_object.digest()

    symmetric_cipher = AES.new(symmetric_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = symmetric_cipher.encrypt_and_digest(plaintext + hmac_digest)
    return ciphertext

def generate_signature(private_key, plaintext):
    """
    Generates a digital signature for the given plaintext using RSA private key.

    :param private_key: The RSA private key.
    :param plaintext: The plaintext message to be signed.
    :return: The digital signature.
    """
    RSA_private_key = RSA.import_key(private_key)
    sha256_hash = SHA256.new(plaintext)
    digital_signature = pkcs1_15.new(RSA_private_key).sign(sha256_hash)
    return digital_signature

def verify_signature(public_key, plaintext, digital_signature):
    """
    Verifies the digital signature of the given plaintext using RSA public key.

    :param public_key: The RSA public key.
    :param plaintext: The plaintext message that was signed.
    :param digital_signature: The digital signature to be verified.
    :return: Message indicating whether the signature is valid or invalid.
    """
    RSA_public_key = RSA.import_key(public_key)
    verification_sha256_hash = SHA256.new(plaintext)
    try:
        pkcs1_15.new(RSA_public_key).verify(verification_sha256_hash, digital_signature)
        return "\nSignature is valid!"
    except (ValueError, TypeError):
        return "\nSignature is invalid!"

# Main script
if __name__ == "__main__":
    symmetric_key = get_random_bytes(16)
    nonce = get_random_bytes(12)

    plaintext = input("Enter your secret message: ").encode()

    # Generate MAC
    mac = generate_mac(symmetric_key, nonce, plaintext)

    # Generate HMAC with ciphertext
    ciphertext_with_digest = generate_hmac(symmetric_key, nonce, plaintext)

    # Generate RSA key pair
    RSA_key = RSA.generate(2048)
    private_key = RSA_key.export_key()
    public_key = RSA_key.publickey().export_key()

    # Generate digital signature
    digital_signature = generate_signature(private_key, plaintext)

    # Print outputs
    print("\nMessage authentication code (MAC):", mac.hex())
    print("\nCiphertext with HMAC:", ciphertext_with_digest.hex())
    print("\nDigital signature:", digital_signature.hex())

    # Verify digital signature
    print(verify_signature(public_key, plaintext, digital_signature))

   
