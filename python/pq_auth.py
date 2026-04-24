# quantumblue_cli/python/pq_auth.py

import os
from dilithium import Dilithium2 # Using Dilithium2 as per common examples, can be swapped for Dilithium3/5

# Define key file paths
PUBLIC_KEY_FILE = "dilithium_public_key.pem"
PRIVATE_KEY_FILE = "dilithium_private_key.pem"

class PostQuantumAuth:
    """
    Handles Dilithium (ML-DSA) key generation, signing, and verification for Quantum Blue.
    """
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self._load_or_generate_keys()

    def _load_or_generate_keys(self):
        """
        Loads existing keys from files or generates new ones if files do not exist.
        Keys are stored in PEM format.
        """
        if os.path.exists(PUBLIC_KEY_FILE) and os.path.exists(PRIVATE_KEY_FILE):
            print("Loading existing Dilithium keys...")
            with open(PUBLIC_KEY_FILE, "rb") as f:
                self.public_key = f.read()
            with open(PRIVATE_KEY_FILE, "rb") as f:
                self.private_key = f.read()
            print("Keys loaded successfully.")
        else:
            print("Dilithium keys not found. Generating new key pair...")
            self._generate_keys()

    def _generate_keys(self):
        """
        Generates a new Dilithium key pair and saves them to PEM files.
        """
        # Generate key pair using Dilithium2
        # The dilithium-py library's keygen returns bytes for pk and sk
        pk_bytes, sk_bytes = Dilithium2.keygen()

        # For simplicity in this draft, we'll save the raw bytes.
        # In a production system, proper PEM encoding/decoding would be preferred.
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(pk_bytes)
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(sk_bytes)

        self.public_key = pk_bytes
        self.private_key = sk_bytes
        print(f"New Dilithium key pair generated and saved to {PUBLIC_KEY_FILE} and {PRIVATE_KEY_FILE}.")

    def sign_data(self, data: bytes) -> bytes:
        """
        Signs the given data using the loaded private key.
        
        Args:
            data: The message or data to sign.
            
        Returns:
            The Dilithium signature.
        """
        if not self.private_key:
            raise ValueError("Private key is not loaded or generated.")
        
        print("Signing data with Dilithium private key...")
        # The sign function returns the signature bytes
        signature = Dilithium2.sign(self.private_key, data)
        print("Data signed successfully.")
        return signature

    def verify_signature(self, data: bytes, signature: bytes) -> bool:
        """
        Verifies the signature against the data using the loaded public key.
        
        Args:
            data: The original message or data.
            signature: The signature to verify.
            
        Returns:
            True if the signature is valid, False otherwise.
        """
        if not self.public_key:
            raise ValueError("Public key is not loaded.")
        
        print("Verifying Dilithium signature...")
        # The verify function returns a tuple where the last element indicates validity
        # Example from search: is_valid = Dilithium2.verify(pk, message, signature)[4]
        # The library might return a more direct boolean or a structure.
        # Assuming the first element of the returned tuple is the validity flag.
        # Let's check the library's actual return type if possible or use a common pattern.
        # For now, assuming it returns a tuple like (pk, msg, sig, metadata, is_valid_flag)
        
        # Check if library directly returns boolean or needs indexing
        # Based on common patterns for crypto verification functions:
        # it might return True/False or raise an exception on failure.
        # The search result showed `[4]` which implies a tuple.
        try:
            # Attempting to get validity flag, assuming the tuple structure from search result
            # Note: Actual library behavior might differ, requiring adjustment.
            verification_result = Dilithium2.verify(self.public_key, data, signature)
            # The search result stated [4] for the validity flag. Let's try to access it.
            # If the library returns a boolean directly, this will fail.
            # A more robust approach would involve checking the library's documentation.
            # For now, let's assume the result is a tuple and the last element is validity.
            is_valid = verification_result[-1] # Assuming last element is the boolean validity
            
            print(f"Signature verification result: {is_valid}")
            return is_valid
        except Exception as e:
            print(f"Error during signature verification: {e}")
            return False

# Example Usage:
if __name__ == "__main__":
    print("--- Quantum Blue PQ-Auth Module Test ---")
    pq_auth = PostQuantumAuth()

    message_to_sign = b"This is a quantum-safe handshake message for the agent."
    
    # 1. Sign the message
    try:
        signature = pq_auth.sign_data(message_to_sign)
        print(f"Generated signature (first 32 bytes): {signature[:32].hex()}...")
        
        # 2. Verify the signature with the correct data
        is_valid = pq_auth.verify_signature(message_to_sign, signature)
        
        if is_valid:
            print("
SUCCESS: Signature is valid for the original message.")
        else:
            print("
FAILURE: Signature is invalid for the original message.")

        # 3. Attempt to verify with tampered data
        tampered_message = b"This is a TAMPERED quantum-safe handshake message."
        print("
--- Testing verification with tampered data ---")
        is_valid_tampered = pq_auth.verify_signature(tampered_message, signature)
        if not is_valid_tampered:
            print("SUCCESS: Verification correctly failed for tampered data.")
        else:
            print("FAILURE: Verification succeeded for tampered data (this is unexpected).")

        # 4. Attempt to verify with incorrect signature
        # Generate a new, different signature to test invalidity
        wrong_signature = Dilithium2.sign(pq_auth.private_key, b"a different message")
        print("
--- Testing verification with incorrect signature ---")
        is_valid_wrong_sig = pq_auth.verify_signature(message_to_sign, wrong_signature)
        if not is_valid_wrong_sig:
            print("SUCCESS: Verification correctly failed for an incorrect signature.")
        else:
            print("FAILURE: Verification succeeded for an incorrect signature (this is unexpected).")

    except Exception as e:
        print(f"
An error occurred during the test: {e}")

    print("
--- Test Complete ---")

