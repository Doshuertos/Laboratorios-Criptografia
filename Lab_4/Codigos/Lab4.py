from Crypto.Cipher import AES
from Crypto.Util.Padding import pad , unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
import binascii

def creacion_Clave(Key, Cifrado):
    if Cifrado == 1 : 
        Tamaño_bytes = 8
    elif Cifrado == 2 : 
        Tamaño_bytes = 32
    elif Cifrado == 3 : 
        Tamaño_bytes = 24

    if len(Key) < Tamaño_bytes : 
        Key += get_random_bytes(Tamaño_bytes - len(Key))
    elif len(Key) > Tamaño_bytes :
        Key = Key[:Tamaño_bytes]

    return Key

def Encriptacion_DES(Key , Vector_IV, Texto) : 
    
    if len(Vector_IV) < 8 : 
        Vector_IV += get_random_bytes(8  - len(Vector_IV))
        
    elif len(Vector_IV) > 8 : 
        Vector_IV = Vector_IV[:8]
        
    Cifrado = DES.new(Key, DES.MODE_CBC,iv = Vector_IV)
    Texto_Con_Padding = pad(Texto,DES.block_size)
    Texto_Cifrado = Cifrado.encrypt(Texto_Con_Padding)
    
    return Texto_Cifrado,Vector_IV

def Encriptacion_3DES(Key , Vector_IV, Texto) : 
    
    if len(Vector_IV) < 8 : 
        Vector_IV += get_random_bytes(8  - len(Vector_IV)) 
        
    elif len(Vector_IV) > 8 : 
        Vector_IV = Vector_IV[:8]
    
    Cifrado = DES3.new(Key, DES3.MODE_CBC,iv = Vector_IV)
    Texto_Con_Padding = pad(Texto,DES3.block_size)
    Texto_Cifrado = Cifrado.encrypt(Texto_Con_Padding)
    
    return Texto_Cifrado,Vector_IV
    
def Encriptacion_AES_256(Key , Vector_IV, Texto) :     
    
    if len(Vector_IV) < 16 : 
        Vector_IV += get_random_bytes(16  - len(Vector_IV)) 
        
    elif len(Vector_IV) > 16 : 
        Vector_IV = Vector_IV[:16]
    
    Cifrado = AES.new(Key, AES.MODE_CBC,iv = Vector_IV)
    Texto_Con_Padding = pad(Texto,AES.block_size)
    Texto_Cifrado = Cifrado.encrypt(Texto_Con_Padding)
    return Texto_Cifrado,Vector_IV

def Desencriptacion_DES(Key, Vector_IV, Texto_Cifrado):
    descifrado = DES.new(Key, DES.MODE_CBC, iv=Vector_IV)
    texto_plano = unpad(descifrado.decrypt(Texto_Cifrado), DES.block_size)
    return texto_plano


def Desencriptacion_3DES(Key, Vector_IV, Texto_Cifrado):
    descifrado = DES3.new(Key, DES3.MODE_CBC, iv=Vector_IV)
    texto_plano = unpad(descifrado.decrypt(Texto_Cifrado), DES3.block_size)
    return texto_plano   
    
def Desencriptacion_AES_256(Key, Vector_IV, Texto_Cifrado):
    descifrado = AES.new(Key, AES.MODE_CBC, iv=Vector_IV)
    texto_plano = unpad(descifrado.decrypt(Texto_Cifrado), AES.block_size)
    return texto_plano    
    
    
    
    
while 1 :
    
    print("Ingrese tipo de Cifrado")
    print("[1] Para DES")
    print("[2] Para AES-256")
    print("[3] para 3DES")
    print("Cualquier otro valor para Salir")
    
    Cifrado = int(input())
    if Cifrado not in [1, 2, 3] :
        break
    Key = input("Ingrese clave a Para cifrar : \n")
    Key = Key.encode('utf-8') #Para pasar a bytes 
    print("LLave Ingresada",Key)
    Valided_Key = creacion_Clave(Key,Cifrado)
    print("LLave Ingresada Validada ",Valided_Key)
    Vector = input("ingrese valor del vector IV : \n")
    Vector = Vector.encode('utf-8')
    
    Texto = input("ingrese texto a para cifrar : \n")
    Texto = Texto.encode('utf-8')
    
    if Cifrado == 1 :
        C_Text,Vector_IV = Encriptacion_DES(Valided_Key,Vector,Texto)
        Texto_Original = Desencriptacion_DES(Valided_Key,Vector_IV,C_Text)
    elif Cifrado == 3 : 
        C_Text,Vector_IV = Encriptacion_3DES(Valided_Key,Vector,Texto)
        Texto_Original = Desencriptacion_3DES(Valided_Key,Vector_IV,C_Text)
    elif Cifrado == 2 :  
        C_Text,Vector_IV = Encriptacion_AES_256(Valided_Key,Vector,Texto)
        Texto_Original = Desencriptacion_AES_256(Valided_Key,Vector_IV,C_Text)
    
    
        
    print("Llave cifrada :",binascii.hexlify(Valided_Key))
    print("Llave cifrada en Hexadecimal :",Valided_Key)   
    print("Texto cifrado :",binascii.hexlify(C_Text))
    print("Texto cifrado en Hexadecimal :",C_Text)
    print("Texto Enviado :",binascii.hexlify(Texto_Original))
    print("Texto Enviado en Hexadecimal :",Texto_Original)
