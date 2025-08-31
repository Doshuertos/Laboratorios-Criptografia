from scapy.all import rdpcap, ICMP, IP

def Descifrado_cesar(Texto_cifrado, Distancia_caracteres):
    mensaje_descifrado = ""
    for caracter in Texto_cifrado:
        if caracter.isalpha():
            Tipo_letra = 65 if caracter.isupper() else 97
            mensaje_descifrado += chr(((ord(caracter) - Tipo_letra - Distancia_caracteres) % 26) + Tipo_letra)
        else:
            mensaje_descifrado += caracter
    return mensaje_descifrado

cap = rdpcap("Lab_1/Datos1.pcapng")

mensaje_bytes = []

for pkt in cap:
    if ICMP in pkt and pkt[ICMP].id == 0xBFF1:
        if IP in pkt and pkt[IP].dst == "8.8.8.8":
            payload = bytes(pkt[ICMP].payload)
            if len(payload) >= 1:
                mensaje_bytes.append((pkt[ICMP].seq, payload[0]))

mensaje_bytes.sort(key=lambda x: x[0])
mensaje = ''.join(chr(b) for seq, b in mensaje_bytes)
mensaje = mensaje[:-1]

print("[+] Mensaje transmitido a 8.8.8.8:")
print(mensaje)

resultados = {}
for i in range(26):
    mensaje_decifrado = Descifrado_cesar(mensaje, i)
    resultados[i] = mensaje_decifrado

def puntuacion(texto):
    letras_comunes = "aeiosrn"
    return sum(texto.lower().count(c) for c in letras_comunes)

mejor_shift, mejor_texto = max(resultados.items(), key=lambda x: puntuacion(x[1]))

print("\n[+] Resultados de descifrado:")
for shift, texto in resultados.items():
    if shift == mejor_shift:
        print(f"\033[92mDesplazamiento {shift}: {texto}\033[0m")
    else:
        print(f"Desplazamiento {shift}: {texto}")
