from scapy.all import rdpcap, ICMP, IP
import re
import unicodedata
from difflib import SequenceMatcher

def Descifrado_cesar(Texto_cifrado, Distancia_caracteres): #Decibra el cifrado ejecutando el inveso a la encriptacion
    mensaje_descifrado = ""
    for caracter in Texto_cifrado:
        if caracter.isalpha():
            Tipo_letra = 65 if caracter.isupper() else 97
            mensaje_descifrado += chr(((ord(caracter) - Tipo_letra - Distancia_caracteres) % 26) + Tipo_letra)
        else:
            mensaje_descifrado += caracter
    return mensaje_descifrado


def normalizar(texto): #Ejecuta una normalizacion para generar un estadar al momento de seleccionar la mas probable
    return ''.join(c for c in unicodedata.normalize('NFD', texto)
                   if unicodedata.category(c) != 'Mn')

with open("Lab_1/spanish_words.txt", encoding="utf-8", errors="ignore") as f: #Se importa un diccionario desde la web para hacer una especie de ataque por diccionario
    palabras_validas = set(word.strip().lower() for word in f if word.strip())

def similitud_palabras(texto): #Puntua las palabras frente a las del diccionario para generar un score entre estas
    texto = normalizar(texto.lower())
    palabras = re.findall(r'\b[a-zA-Z]+\b', texto)
    score = 0
    for palabra in palabras:
        similitudes = [SequenceMatcher(None, palabra, dic_word).ratio() for dic_word in palabras_validas]
        if similitudes:
            score += max(similitudes)
    return score

def reconstruir_mensaje(pcap_file, icmp_id=0xBFF1, dst_ip="8.8.8.8"): #Recontruye el conjunto de paquetes enviados
    cap = rdpcap(pcap_file)
    mensaje_bytes = []
    for pkt in cap:
        if ICMP in pkt and pkt[ICMP].id == icmp_id:
            if IP in pkt and pkt[IP].dst == dst_ip:
                payload = bytes(pkt[ICMP].payload)
                if len(payload) >= 1:
                    mensaje_bytes.append((pkt[ICMP].seq, payload[0]))
    mensaje_bytes.sort(key=lambda x: x[0])
    mensaje = ''.join(chr(b) for seq, b in mensaje_bytes)
    return mensaje[:-1]  # eliminar pla "b" que se pone en el anteiror punto


def descifrar_cesar_mensaje(mensaje): #Ejecuta el ataque de fuerza bruta 
    resultados = {}
    for i in range(26):
        texto = Descifrado_cesar(mensaje, i)
        resultados[i] = texto

    scores = {shift: similitud_palabras(texto) for shift, texto in resultados.items()}

    mejor_shift = max(scores, key=scores.get)
    return resultados, mejor_shift


pcap_file = "Lab_1/Ejemplo_lab.pcapng"  
mensaje = reconstruir_mensaje(pcap_file)
print("[+] Mensaje transmitido a 8.8.8.8 (cifrado):")
print(mensaje)

resultados, mejor_shift = descifrar_cesar_mensaje(mensaje)


print("\n[+] Resultados de descifrado:")
for shift, texto in resultados.items():
    if shift == mejor_shift:
        print(f"\033[92mShift {shift}: {texto}\033[0m")  
    else:
        print(f"Shift {shift}: {texto}")
