from Crypto.Util.number import getPrime, long_to_bytes, bytes_to_long
from random import randint
from Crypto.Util.number import GCD
from secret import sda3
with open("flag.txt", 'r') as f:
    flag = f.read()

Messages = []
p = getPrime(1024)
g = 3
k = randint(2, p - 2)
x = randint(1, p - 2)
y = pow(g, x, p)
o=0

while o==0:
    if GCD(k, p - 1) != 1:
        k = randint(2, p - 2)
        continue
    else:
        o=1    
                
def gen_keys():
    return (x, y, p, g)
    
def sign(answer: int, x: int):
    while True:
        m = answer
       
        r = pow(g, k, p)
        s = (m - x * r) * pow(k, -1, p - 1) % (p - 1)
        assert(GCD(r, p - 1)==1)
        if s == 0:
            continue
        return (r, s)

def verify(answer, r, s):
    m = answer
    if any([x <= 0 or x >= p - 1 for x in [m, r, s]]):
        return False
    return pow(g, m, p) == (pow(y, r, p) * pow(r, s, p)) % p

def intercept():
    m = randint(0, getPrime(1000) - 1)
    r, s = sign(m, x)
    _, y, p, g = gen_keys()
    return r, s, m, y, p, g

small=[]

def main():
    i = 0
    while i < 3:
        if i==2:
            if sda3(small,p) :
                print("all good")
            else:
                print("Wa ykon khir ykon khir. Something is seeking coprimalitytyty")
                return 0
        x, y, p, g = gen_keys()
        inp = int(input('khtar: '))
        r, s, m, y, p, g = intercept()
        small.append(s)
        Messages.append(m)

        if inp == 1:
            print(f"[{r}, {s}, {m}, {y}, {p}, {g}]")
        elif inp == 2:
            inp2 = input('Prove that nta howa nta: ').split(',')
            m1, r1, s1, y = [int(i) for i in inp2]
            if m1 in Messages:
                return 0
            elif verify(m1, r1, s1):
                print(flag)
            else:
                return 0
        else:
            return 0
        i+=1
if __name__ == "__main__":
    main()
