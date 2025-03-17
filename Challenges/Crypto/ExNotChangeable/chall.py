from Crypto.Util.number import getPrime, bytes_to_long, isPrime
import random

flag=bytes_to_long(b"MCSC{fake_flag}")
p = getPrime(512) 
g = 2

def SlowDown(number, total_bits, look):
    lookhere = total_bits - look
    role = (number >> lookhere) & ((1 << look) - 1)
    return role << lookhere  


try:
        E = random.randint(100,270)
        a = random.randint(1, p-1)
        b = random.randint(1, p-1)
        c = random.randint(1, p-1)
        A = pow(g, a, p)
        B = pow(g, b, p)
        s = pow(B, a, p)
        D=pow(g,(a+c)*b,p)



        rrrrrr = SlowDown(s,512,E)
        bakha = SlowDown(D,512,E)

        print("g =", hex(g))
        print("B =", hex(B))
        print("p =",p)
        print("rrrrrr =",hex(rrrrrr))
        print("bakha =",hex(bakha))
        print("c =", hex(c))
        t=getPrime(512)
        while  isPrime(s) == False:
            s+=1
        n=t*s
        print("ExNotChangeable =", pow(flag,65537,n))
        print("n =",n)
        exit()
        
except:
        pass    
        

