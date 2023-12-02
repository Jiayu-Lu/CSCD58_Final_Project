import time

import scapy.all as scapy

from utils.static_definitions import PROTOCOL_MAP
from utils.utils import port_to_service

class TrimmedPacket():
    def __init__(self, packet: scapy.Packet):

        if scapy.TCP not in packet:
            raise ValueError("Packet has no TCP layer")
        if scapy.IP not in packet:
            raise ValueError("Packet has no IP layer")
        
        self.flags = packet[scapy.TCP].flags
        self.syn: bool = "S" in self.flags

        self.recieved: float = time.time()
        self.protocol: int = PROTOCOL_MAP["tcp"]

        self.size = len(packet[scapy.TCP].payload)
        self.flags = packet[scapy.TCP].flags
        self.src_port = packet[scapy.TCP].sport
        self.dst_port = packet[scapy.TCP].dport
        self.service: str | None = port_to_service(self.dst_port)

        if self.service is None:
            self.service = port_to_service(self.src_port)

        self.src_ip = packet[scapy.IP].src
        self.dst_ip = packet[scapy.IP].dst

        self.data: str | None = packet[scapy.Raw].load.decode("utf-8") if scapy.Raw in packet else None

    def __str__(self):
        msg = f"{self.protocol} packet of size {self.size} using service {self.service}\n"
        msg += f"\tflags: {self.flags}\n"
        msg += f"\tsource: {self.src_ip}:{self.src_port}\n"
        msg += f"\tdest: {self.dst_ip}:{self.dst_port}\n"
        msg += f"\tdata: {self.data}\n"
        return msg
        