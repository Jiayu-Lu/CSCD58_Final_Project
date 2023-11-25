import scapy.all as scapy
import threading
import time

from queue import Queue
from collections import deque

from objects.trimmed_packet import TrimmedPacket
from objects.tcp_connection import TCPConnection
from settings import IF_NAME, FILTER_STR

'''
Ideally we want to use this class to monitor traffic going into a single server,
this way we can isolate/detect attacks happening to a single server. We can also demo and simulate attacks
on a simple server. To isolate traffic we can filter our sniff to only show the ones going to our server
IP/Port
'''
class PacketCapture():

    def __init__(self, timeout:float = (2**32 - 1)):
        self.packets: Queue[scapy.packet.Packet] = Queue()
        self.timeout: float = timeout

    def received_packet(self, packet):
        # print(packet)
        self.packets.put(TrimmedPacket(packet))

    def run(self):
        connection_window: deque[TCPConnection] = deque()
        active_connection: TCPConnection = None
        oldest_connection: float = None

        t = threading.Thread(target=self.start_sniff)
        t.start()
        generator = self.retrieve_packets()

        for packet in generator:
            if "S" in packet[scapy.TCP]:
                # need to check if different connection if we have active
                active_connection = TCPConnection()
            elif active_connection and "F" in packet[scapy.TCP]:
                active_connection.close_connection()
                connection_window.append(active_connection)
            #elif active_connection
            



        


    def retrieve_packets(self):
        start = time.time()
        while (time.time() - start) < self.timeout:
            packet = self.packets.get(block=True)
            if scapy.TCP in packet:
                yield packet

        return


            









    def start_sniff(self):
        scapy.sniff(iface=IF_NAME, prn=self.received_packet, filter=FILTER_STR)


