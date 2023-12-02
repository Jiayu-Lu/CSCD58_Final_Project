import requests

from scapy.all import send, IP, TCP, Raw, sr1
from settings import IF_NAME, SERVER_IP, SERVER_PORT, ATTACK_SERVER_IP, ATTACK_SERVER_PORT

class SimulationRunner():

    def __init__(self):
        pass

    def request_resource(self):
        requests.get(f"http://{SERVER_IP}:{SERVER_PORT}")

    def send_packet(self, destination_ip, source_port, destination_port, data, flags):
        ip = IP(dst=destination_ip)
        tcp = TCP(sport=source_port, dport=destination_port, flags=flags)
        raw = Raw(load=data)
        packet = ip/tcp/raw
        sr1(packet)

        print(f"Sent {flags} packet to {destination_ip}:{destination_port}")