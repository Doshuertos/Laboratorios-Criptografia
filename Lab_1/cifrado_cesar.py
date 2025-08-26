def Cifrado_cesar(Texto,Distancia_caracteres):
    mensaje_cifrado= ""
    for caracter in Texto :

        if caracter.isalpha() :

            Tipo_letra = 65 if caracter.isupper() else 97 #Define si es mayuscula o minuscula

            mensaje_cifrado += chr(((ord(caracter))-Tipo_letra+Distancia_caracteres) % 26 + Tipo_letra) #Cifrado

            # %26 para que solo se mantenga en el alfabeto tanto superior como inferior 

        else :

            mensaje_cifrado+= caracter

    return mensaje_cifrado


Texto_A_Cifrar = input("Ingrese el mensaje a cifrar ")
Distancia = int(input("Ingrese la distancia a utilizar"))
Cifrado = Cifrado_cesar(Texto_A_Cifrar,Distancia)

print("El mensaje cifrado es", Cifrado)
