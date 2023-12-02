import scapy.all as scapy
import threading
import time

from queue import Queue
from collections import deque

from objects.trimmed_packet import TrimmedPacket
from objects.tcp_connection import TCPConnection
from settings import (IF_NAME, FILTER_STR, ATTACK_SERVER_IP, 
                      ATTACK_SERVER_PORT, CONNECTION_WINDOW, SERVER_IP, SERVER_PORT)
from utils.static_definitions import CONNECTION_DATA_NAMES, FLAG_MAP
from utils.algorithms import Algorithms

from attack_detection.ids import IDS

'''
Ideally we want to use this class to monitor traffic going into a single server,
this way we can isolate/detect attacks happening to a single server. We can also demo and simulate attacks
on a simple server. To isolate traffic we can filter our sniff to only show the ones going to our server
IP/Port
'''


class PacketCapture():

    def __init__(self, algo: Algorithms, timeout: float = (2 ** 32 - 1), detect_interval: int = 1000):
        self.timeout: float = timeout
        # The time interval that we pop captured from queue, process each packet and run ML model (in milliseconds)
        self.detect_interval: float = detect_interval / 1000

        # temporarily store packet for processing
        self.packet_process_queue: Queue[scapy.packet.Packet] = Queue()
        # current established tcp connection
        self.current_connection: TCPConnection = None
        # previously established connection
        self.connection_window: deque[TCPConnection] = deque()

        self.ids = IDS(algo)

        # Flag to indicate intrusion detection
        # will stop capturing packets if intrusion_detected is false
        self.intrusion_detected: bool = False

        # lock of packet process queue to ensure thread-safe access
        # self.queue_lock = threading.Lock()

        self.oldest_connection: float = -1

    # Method to start packet capture and packet analysis threads
    def run(self):
        print("Starting Packet Capture!")
        packet_sniff = threading.Thread(target=self.start_sniff)
        # analyze_packet = threading.Thread(target=self.analyze_packet)

        packet_sniff.start()
        # analyze_packet.start()
        self.analyze_packet()


    def detect_intrusion(self):
        if self.current_connection is not None:
            print("Predicting")
            print(self.ids.classify_connection(self.current_connection))

    def analyze_packet(self):
        prev: float = time.time()
        start: float = time.time()

        # This is where we extract packet data
        while time.time() - start < self.timeout:
            packet = self.packet_process_queue.get()
            # print("Got packet!")
            self.process_packet(packet)
            t = time.time()
            if t - prev > self.detect_interval:
                prev = t
                self.detect_intrusion()

    def process_packet(self, packet: scapy.packet.Packet):

        trimmed_packet = TrimmedPacket(packet)

        if "S" in trimmed_packet.flags:
            if self.current_connection is not None:
                self.close_current_connection()
            self.current_connection = self.create_tcp_connection(trimmed_packet)
        elif "F" in trimmed_packet.flags:
            if self.current_connection is not None:
                self.current_connection.fin = True
                self.close_current_connection()
        elif self.current_connection is not None:
            self.current_connection.add_packet(packet)

    def start_sniff(self):
        scapy.sniff(iface=IF_NAME, prn=self.queue_packet, store=0)

    # Method for processing captured packets
    def queue_packet(self, packet: scapy.packet.Packet):
        # Filter string does not work for me?
        if scapy.TCP not in packet:
            return
        if scapy.IP not in packet:
            return
        if packet[scapy.IP].src != ATTACK_SERVER_IP:
            return
        if packet[scapy.IP].dst != SERVER_IP:
            return
        # if packet[scapy.TCP].sport != ATTACK_SERVER_PORT:
        #     return
        # if packet[scapy.TCP].dport != SERVER_PORT:
        #     return

        self.packet_process_queue.put(packet)

        # trimmed_packet = TrimmedPacket(packet)
        # # print(f"captured packet:  {trimmed_packet}")
        # # print(trimmed_packet.data)

        # if "S" in trimmed_packet.flags:
        #     self.queue_s_packet(trimmed_packet)
        # elif "F" in trimmed_packet.flags:
        #     self.queue_f_packet(trimmed_packet)
        # elif self.current_connection is not None:
        #     # add packet to queue
        #     self.packet_process_queue.put(trimmed_packet)

    def queue_s_packet(self, trimmed_packet: TrimmedPacket):
        # initialize a new connection and add packet to queue
        if self.current_connection is not None:
            self.close_current_connection()

        # print("STARTING NEW CONNECTION")
        self.current_connection = self.create_tcp_connection(trimmed_packet)
        # self.packet_process_queue.put(trimmed_packet)

    def queue_f_packet(self, trimmed_packet: TrimmedPacket):
        # add packet to queue
        # self.packet_process_queue.put(trimmed_packet)
        # print("ENDING CONNECTION")
        if self.current_connection is not None:
            self.current_connection.fin = True
            self.close_current_connection()

    def close_current_connection(self):
        
        self.current_connection.close_connection()
        self.connection_window.append(self.current_connection)

        if self.oldest_connection == -1.0:
            self.oldest_connection = self.current_connection.end_time
        else:
            while time.time() - self.oldest_connection > CONNECTION_WINDOW:
                self.connection_window.popleft()
                if not self.connection_window:
                    self.oldest_connection == -1.0
                    break
                self.oldest_connection = self.connection_window[0].end_time

        # self.detect_intrusion()
        self.current_connection = None

    def create_tcp_connection(self, trimmed_packet: TrimmedPacket) -> TCPConnection:
        data = self.calc_stats(trimmed_packet)
        count_same = 1 if data["count_same"] == 0 else data["count_same"]
        dst_host_count = 1 if data["dst_host_count"] == 0 else data["dst_host_count"]
        return TCPConnection(trimmed_packet.protocol,
                             trimmed_packet.src_ip,
                             trimmed_packet.src_port,
                             trimmed_packet.dst_ip,
                             trimmed_packet.dst_port,
                             trimmed_packet.service,
                             trimmed_packet.src_ip == trimmed_packet.dst_ip and trimmed_packet.src_port == trimmed_packet.dst_port,
                             count_same,
                             data["serror_count"] / count_same,
                             data["rerror_count"] / count_same,
                             data["same_srv_count"] / count_same,
                             data["diff_srv_count"] / count_same,
                             dst_host_count,
                             data["dst_host_srv_count"],
                             data["dst_host_diff_srv_count"] / dst_host_count,
                             data["dst_host_same_src_port_count"] / dst_host_count,
                             data["dst_host_diff_src_port_count"] / dst_host_count,
                             data["same_srv_count"]
                )



    def calc_stats(self, syn_packet: TrimmedPacket):
        data = dict.fromkeys(CONNECTION_DATA_NAMES, 0)

        for connection in self.connection_window:
            if connection.source_ip == syn_packet.src_ip:
                data["count_same"] += 1
                if connection.flag == FLAG_MAP["S0"]:
                    data["serror_count"] += 1
                if connection.flag == FLAG_MAP["REJ"]:
                    data["rerror_count"] += 1
                if syn_packet.service == connection.service:
                    data["same_srv_count"] += 1
                else:
                    data["diff_srv_count"] += 1
            if syn_packet.dst_ip == connection.dest_ip:
                data["dst_host_count"] += 1
                if syn_packet.service == connection.service:
                    data["dst_host_srv_count"] += 1
                else:
                    data["dst_host_diff_srv_count"] += 1
                if syn_packet.dst_port == connection.dest_port:
                    data["dst_host_same_src_port_count"] += 1
                else:
                    data["dst_host_diff_src_port_count"] += 1


        return data








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
