import scapy.all as scapy
import threading
import time

from queue import Queue
from collections import deque

from objects.trimmed_packet import TrimmedPacket
from objects.tcp_connection import TCPConnection
from settings import IF_NAME, FILTER_STR, ATTACK_SERVER_IP, ATTACK_SERVER_PORT

'''
Ideally we want to use this class to monitor traffic going into a single server,
this way we can isolate/detect attacks happening to a single server. We can also demo and simulate attacks
on a simple server. To isolate traffic we can filter our sniff to only show the ones going to our server
IP/Port
'''


class PacketCapture():

    def __init__(self, target_ip, target_port, timeout: float = (2 ** 32 - 1), detect_interval: float = 2):
        self.timeout: float = timeout
        # The time interval that we pop captured from queue, process each packet and run ML model
        self.detect_interval = detect_interval

        # The ip and port of the attacker
        # Might remove port later since we're testing on localhost
        self.target_ip = target_ip
        self.target_port = target_port

        # temporarily store packet for processing
        self.packet_process_queue = Queue()
        # current established tcp connection
        self.current_connection = None
        # previously established connection
        self.connection_window: deque[TCPConnection] = deque()

        # Flag to indicate intrusion detection
        # will stop capturing packets if intrusion_detected is false
        self.intrusion_detected = False

        # lock of packet process queue to ensure thread-safe access
        self.queue_lock = threading.Lock()

    # Method to start packet capture and packet analysis threads
    def run(self):
        packet_sniff = threading.Thread(target=self.start_sniff)
        analyze_packet = threading.Thread(target=self.analyze_packet)

        packet_sniff.start()
        analyze_packet.start()


    def detect_intrusion(self):
        print("run our models here")

    def analyze_packet(self):
        while not self.intrusion_detected:
            time.sleep(self.detect_interval)

            # This is where we extract packet data
            while not self.packet_process_queue.empty():
                packet = self.packet_process_queue.get()
                print(f"pop packet:  {packet}")

            self.detect_intrusion()

    def start_sniff(self):
        while not self.intrusion_detected:
            scapy.sniff(iface=IF_NAME, prn=self.queue_packet,
                        filter=FILTER_STR + f" and host {self.target_ip} and port {self.target_port}")

    # Method for processing captured packets
    def queue_packet(self, packet):
        trimmed_packet = TrimmedPacket(packet)
        # print(f"captured packet:  {trimmed_packet}")

        if "S" in trimmed_packet.flags:
            self.queue_s_packet(trimmed_packet)
        elif "F" in trimmed_packet.flags:
            self.queue_f_packet(trimmed_packet)
        else:
            # add packet to queue
            self.packet_process_queue.put(trimmed_packet)

    def queue_s_packet(self, trimmed_packet):
        # initialize a new connection and add packet to queue
        self.current_connection = TCPConnection()
        self.packet_process_queue.put(trimmed_packet)

    def queue_f_packet(self, trimmed_packet):
        # add packet to queue
        self.packet_process_queue.put(trimmed_packet)

        # close connection and append closed-connection to connection window
        self.current_connection.close_connection()
        self.connection_window.append(self.current_connection)



if __name__ == "__main__":
    packet_capture = PacketCapture(ATTACK_SERVER_IP, ATTACK_SERVER_PORT)
    packet_capture.run()

    # def run(self):
    #     t = threading.Thread(target=self.start_sniff)
    #     t.start()
    #     generator = self.retrieve_packets()
    #
    #     for packet in generator:
    #         if "S" in packet[scapy.TCP]:
    #             # need to check if different connection if we have active
    #             current_connection = TCPConnection()
    #             self.connection_window.append(current_connection)
    #             current_connection.add_packet(packet)
    #             active_connection = TCPConnection()
    #         elif active_connection and "F" in packet[scapy.TCP]:
    #             active_connection.close_connection()
    #             connection_window.append(active_connection)
    #         #elif active_connection
    #
    # def received_packet(self, packet):
    #     # print(packet)
    #     self.packets.put(TrimmedPacket(packet))
    #
    # def retrieve_packets(self):
    #     start = time.time()
    #     while (time.time() - start) < self.timeout:
    #         packet = self.packets.get(block=True)
    #         if scapy.TCP in packet:
    #             yield packet
    #
    #     return
    #
    # def start_sniff(self):
    #     scapy.sniff(iface=IF_NAME, prn=self.received_packet, filter=f"src host {target_ip}")
