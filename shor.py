import hashlib
import ecdsa
import base58
import random
import sys

def private_key_to_wif(private_key_hex):
    private_key = bytes.fromhex(private_key_hex)
    extended_key = b'\x80' + private_key
    first_sha256 = hashlib.sha256(extended_key).digest()
    second_sha256 = hashlib.sha256(first_sha256).digest()
    checksum = second_sha256[:4]
    wif = base58.b58encode(extended_key + checksum)
    return wif

def private_key_to_public_key(private_key_hex):
    private_key = bytes.fromhex(private_key_hex)
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()
    return public_key

def public_key_to_address(public_key):
    sha256_1 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_1)
    hashed_public_key = ripemd160.digest()
    pre_address = b'\x00' + hashed_public_key
    sha256_2 = hashlib.sha256(pre_address).digest()
    sha256_3 = hashlib.sha256(sha256_2).digest()
    checksum = sha256_3[:4]
    address = base58.b58encode(pre_address + checksum)
    return address.decode('utf-8')

def generate_random_private_key():
    return ''.join([random.choice('0123456789abcdef') for _ in range(64)])

def brute_force_private_key(target_address):
    import time

    start_time = time.time()
    attempts = 0

    while True:
        attempts += 1
        private_key = generate_random_private_key()
        public_key = private_key_to_public_key(private_key)
        address = public_key_to_address(public_key)

        if address == target_address:
            elapsed_time = time.time() - start_time
            print(f"Private key found after {attempts} attempts in {elapsed_time:.2f} seconds!")
            print(f"Private key (hex): {private_key}")
            print(f"Address: {address}")
            return private_key

        if attempts % 100000 == 0:
            elapsed_time = time.time() - start_time
            print(f"{attempts} attempts in {elapsed_time:.2f} seconds")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python bruteforce_private_key.py <target_address>")
        sys.exit(1)

    target_address = sys.argv[1]
    brute_force_private_key(target_address)
