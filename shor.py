import subprocess
import os

# Fonction pour lancer le script en arrière-plan
def run_in_background(address):
    script = f"""
import numpy as np
from fractions import Fraction
from hashlib import sha256

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def shors_algorithm_for_bitcoin(address):
    public_key_hash = sha256(address.encode()).hexdigest()
    N = int(public_key_hash, 16) % 2**16  # Just for demonstration
    print(f"Simulating factorization for N={{N}}")
    factors = shors_algorithm(N)
    if factors:
        print(f"Found factors for simulated N: {{factors}}")
    else:
        print("Failed to find factors for the simulated N.")
    return factors

def shors_algorithm(N):
    a = np.random.randint(2, N)
    while gcd(a, N) != 1:
        a = np.random.randint(2, N)
    r = find_period(a, N)
    if r is None:
        print(f"Failed to find the period for a={{a}}")
        return None
    if r % 2 != 0 or pow(a, r // 2, N) == N - 1:
        print(f"Invalid period found for a={{a}}, retrying...")
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

bitcoin_address = "{address}"
shors_algorithm_for_bitcoin(bitcoin_address)
"""
    script_path = "shor_simulation.py"
    log_file = "shor_simulation.log"

    # Ecrire le script dans un fichier
    with open(script_path, "w") as file:
        file.write(script)

    # Commande pour exécuter le script en arrière-plan
    command = ["python", script_path]

    # Rediriger la sortie standard et les erreurs vers un fichier log
    with open(log_file, "w") as log:
        process = subprocess.Popen(command, stdout=log, stderr=log, close_fds=True)

    print(f"Script is running in the background. Logs are written to {log_file}.")

# Adresse Bitcoin cible
bitcoin_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
run_in_background(bitcoin_address)
