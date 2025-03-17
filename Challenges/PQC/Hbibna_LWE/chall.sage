import numpy as np
from hashlib import sha256

n = 40   
m = 80 
q = 32768 
sigma = 3 

def lbeast():
    s = np.random.randint(-1, 2, size=(n, 1), dtype=np.int64)
    A = np.random.randint(0, q, size=(m, n), dtype=np.int64)
    e = np.round(sigma * np.random.randn(m, 1)).astype(np.int64)
    b = (A @ s + e) % q
    b = b.ravel()
    
    return A, b, s

def encrypt_flag(s, flag):
    s_bytes = s.tobytes()
    key = sha256(s_bytes).digest()
    encrypted = bytes([f ^ k for f, k in zip(flag, key)])
    return encrypted

if __name__ == "__main__":
    A, b, s = lbeast()
    
    flag = b"MCSC{OK}" 
    encrypted_flag = encrypt_flag(s, flag)
    np.savez("lwe_challenge_final.npz",
             A=A,
             b=b,
             encrypted_flag=np.frombuffer(encrypted_flag, dtype=np.uint8))
    
   
