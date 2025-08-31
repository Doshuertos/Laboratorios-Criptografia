import random
from scapy.all import IP, ICMP, send
import time
import struct

mensaje = "larycxpajorj h bnpdarmjm nw anmnb "  # Mensaje a enviar
ip_destino = "8.8.8.8"  # IP a utilizar
Base_payload = bytes([
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
]) #Bytes del 0x10 hasta el 0x37
id_mensaje = 0xBFF1
ts_bytes = struct.pack("d", time.time())  # 8 bytes timestamp

for i, caracter in enumerate(mensaje):
    payload = bytes([ord(caracter)]) + Base_payload
    payload += ts_bytes
    Mensaje_a_Enviar = IP(dst = ip_destino)/ICMP(id = id_mensaje, seq = i)/payload
    send(Mensaje_a_Enviar)
    time.sleep(0.1)
    print(f"Paquete {i}: letra='{caracter}' (0x{ord(caracter):02X}), ICMP seq={i}, ID={hex(id_mensaje)}")


Ultimo_caracter = 'b'
ultimo_payload = bytes([ord(Ultimo_caracter)]) + Base_payload
ultimo_mensaje = IP(dst=ip_destino)/ICMP(id=id_mensaje, seq=len(mensaje))/ultimo_payload
send(ultimo_mensaje)
print(f"Paquete {len(mensaje)}: letra='{Ultimo_caracter}' (0x{ord(Ultimo_caracter):02X}), ICMP seq={len(mensaje)}, ID={hex(id_mensaje)}")





    