from secret import garbages
flag = open("flag.txt", "rb").read()


class Lib:
    def __init__(self):
        self.name = "Sn4keEy3s"
        self.s = "frelaaaaaglace" 
        self.book = "Visaaaalmarrroc"
        self.price = "goaalooooljjbkkkakkklcarssuuuuu"
    def __str__(self):
        return self.name
    def ro(self):
        return self.s
    
    
class Lib1:
    def __init__(self):
        self.name = "Sn4keEy3s"
        self.s = "flllaaaaaglace" 
        self.book = "Visaaaalmarrroc"
        self.price = "goaalooooljjbkkkakkklcarssuuuuu"
    def __str__(self):
        return self.name
   
    def ko(self):
        return self.price 

class I(Lib):
    pass
class N(Lib):
    pass
class S(Lib1):
    pass
class E(Lib1):
    pass
class C(Lib1):
    pass
    

baite1=input('wa thala fia nthala fik 1 : ')  
if len(baite1)>16 or any(char in baite1 for char in ['f', '/', '-',' ','rm','#','c','r','p','l']) :
   print('nchaalah brabi')
   exit(0)
declared_str1 = eval(baite1,{"__builtins__": None},garbages)
baite2=input('wa thala fia nthala fik 2 : ') 
if len(baite2)>16 or any(char in baite2 for char in ['f', '/', '-',' ','rm','#','d','c','p','l'])     : 
   print('nchaalah brabi')
   exit(0)
declared_str2 = eval(baite2,{"__builtins__": None},garbages)
def main():
    while True:
        inp = input("") 
        if any(char in inp for char in ['f', '/', '-','l']):
           print('nchaalah brabi')
           return 0
        formatted_str = inp.replace('garbage2', str(globals().get('declared_str2'))).replace('garbage', str(globals().get('declared_str1')))
        formatted_str = formatted_str.format(a=Lib())
        
        print(formatted_str) 

if __name__ == "__main__":
    main()

