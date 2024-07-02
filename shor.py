import OpenSSL.crypto
import numpy as np
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def get_modulus_from_public_key(public_key_path):
    with open(public_key_path, 'r') as f:
        pubkey_data = f.read()
    pubkey_obj = OpenSSL.crypto.load_publickey(OpenSSL.crypto.FILETYPE_PEM, pubkey_data)
    pubkey_str = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, pubkey_obj).decode()

    print("Detected RSA key.")
    pubkey_asn1 = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1, pubkey_obj)
    
    # Decode ASN.1 DER format
    pubkey_der = pubkey_asn1
    modulus_start = pubkey_der.find(b'\x02\x82')
    if modulus_start == -1:
        raise ValueError("Unsupported RSA public key format")
    
    modulus_length = int.from_bytes(pubkey_der[modulus_start + 2:modulus_start + 4], 'big')
    modulus = pubkey_der[modulus_start + 4:modulus_start + 4 + modulus_length]

    modulus_hex = modulus.hex()

    return modulus_hex, "RSA"

def shors_algorithm_for_rsa(modulus_hex):
    N = int(modulus_hex, 16)
    print(f"Simulating factorization for N={N}")
    factors = shors_algorithm(N)
    if factors:
        print(f"Found factors for N: {factors}")
        p, q = factors
        return derive_private_key(p, q, N)
    else:
        print("Failed to find factors for N.")
    return None

def shors_algorithm(N):
    a = np.random.randint(2, N)
    while gcd(a, N) != 1:
        a = np.random.randint(2, N)
    r = find_period(a, N)
    if r is None:
        print(f"Failed to find the period for a={a}")
        return None
    if r % 2 != 0 or pow(a, r // 2, N) == N - 1:
        print(f"Invalid period found for a={a}, retrying...")
        return None
    factor1 = gcd(pow(a, r // 2) - 1, N)
    factor2 = gcd(pow(a, r // 2) + 1, N)
    if factor1 == N or factor1 == 1:
        return None
    if factor2 == N or factor2 == 1:
        return None
    return factor1, factor2

def find_period(a, N):
    x = 1
    r = 0
    while x != 1 or r == 0:
        x = (x * a) % N
        r += 1
        if r > 2 * N:
            return None
    return r

def derive_private_key(p, q, N):
    phi = (p - 1) * (q - 1)
    e = 65537  # Commonly used public exponent
    d = modinv(e, phi)
    if d is None:
        print("Failed to compute the modular inverse.")
        return None
    return {
        'p': p,
        'q': q,
        'e': e,
        'd': d,
        'n': N
    }

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        return None
    else:
        return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y

def print_private_key_components(components):
    print("Private Key Components:")
    print(f"p: {components['p']}")
    print(f"q: {components['q']}")
    print(f"e: {components['e']}")
    print(f"d: {components['d']}")
    print(f"n: {components['n']}")

def pauli_x(qubit):
    """Simulates the Pauli-X (NOT) gate"""
    return qubit ^ 1

def pauli_z(qubit):
    """Simulates the Pauli-Z gate"""
    return qubit

def hadamard(qubit):
    """Simulates the Hadamard gate"""
    return np.random.choice([0, 1])

def simulate_qecdl_algorithm(pubkey_hex):
    """Simulates a quantum algorithm for breaking ECDSA keys using bitwise operations"""
    print("Executing Quantum Elliptic Curve Discrete Logarithm Algorithm (QECDLA) simulation...")

    # Simulating the quantum operations
    qubits = [int(bit) for bit in bin(int(pubkey_hex, 16))[2:].zfill(256)]
    
    # Apply Hadamard gate to all qubits to create superposition
    qubits = [hadamard(qubit) for qubit in qubits]
    
    # Apply Pauli-X gate to some qubits
    qubits = [pauli_x(qubit) if np.random.random() > 0.5 else qubit for qubit in qubits]
    
    # Apply Pauli-Z gate to some qubits
    qubits = [pauli_z(qubit) if np.random.random() > 0.5 else qubit for qubit in qubits]
    
    # Combine the qubits back into a simulated private key (for demonstration purposes)
    private_key_bin = ''.join(map(str, qubits))
    private_key = hex(int(private_key_bin, 2))

    return private_key


# Main function to handle argument and process the certificate
def main(cert_file):
    try:
        key_hex, key_type = get_modulus_from_public_key(cert_file)
    except ValueError as e:
        print(e)
        return
    
    if key_type == "RSA":
        private_key_components = shors_algorithm_for_rsa(key_hex)
        if private_key_components:
            print_private_key_components(private_key_components)
    elif key_type == "ECDSA":
        private_key = simulate_qecdl_algorithm(key_hex)
        print("Derived ECDSA Private Key (simulated):")
        print(private_key)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python shor.py <path_to_certificate.pem>")
        sys.exit(1)
    cert_file = sys.argv[1]
    main(cert_file)
