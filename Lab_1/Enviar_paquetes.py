from scapy.all import IP, ICMP, send

def stealth_ping(message, dst_ip):
    for char in message + "b":
        packet = IP(dst=dst_ip)/ICMP()/char.encode() #Armado del paquete ICMP
        send(packet, verbose=False) #Paquete enviado
        print(f"[+] Enviado: {char} -> {dst_ip}")

if __name__ == "__main__":
    mensaje = "larycxpajorj h bnpdarmjm nw anmnb "  #Mensaje a enviar
    ip_destino = "8.8.8.8"  #Ip a utilzar
    stealth_ping(mensaje, ip_destino)
