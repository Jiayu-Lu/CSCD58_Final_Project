import scapy.all as scapy
import threading
import time

from queue import Queue
from objects.trimmed_packet import TrimmedPacket
from settings import IF_NAME, FILTER_STR

def print_packets_interval(packets):
    t = time.time()
    print("running")
    count = 0

    while count < 10:
        if time.time() - t >= 1:
            print(packets)
            t = time.time()
            count += 1

class PacketCapture():

    def __init__(self, timeout:float = (2**32 - 1)):
        self.packets = Queue()
        self.timeout = timeout

    def received_packet(self, packet):
        # print(packet)
        self.packets.put(TrimmedPacket(packet))

    def run(self):
        t = threading.Thread(target=self.start_sniff)
        t.start()
        start = time.time()

        packet_window = []

        while (time.time() - start) < self.timeout:
            item = self.packets.get(block=True)

            









    def start_sniff(self):
        scapy.sniff(iface=IF_NAME, prn=self.received_packet, filter=FILTER_STR)


