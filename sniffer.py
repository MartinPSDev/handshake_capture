from scapy.all import *

def packet_handler(packet):
    if packet.haslayer(Dot11):
        print(f"Tipo de frame: {packet.type}, Subtipo: {packet.subtype}")
        print(f"Dirección BSSID: {packet.addr1}")
        print(f"Dirección STA: {packet.addr2}")
        print(f"SSID: {packet.info}")
        print("-----------------------------------")

# Capturar todos los paquetes 802.11 en la interfaz wlan0
sniff(iface="Wi-Fi", prn=packet_handler, store=0)