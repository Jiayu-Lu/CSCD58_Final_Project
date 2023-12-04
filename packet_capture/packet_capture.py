import scapy.all as scapy
import threading
import time

from queue import Queue
from collections import deque

from objects.trimmed_packet import TrimmedPacket
from objects.tcp_connection import TCPConnection
from settings import (
    IF_NAME,
    ATTACK_SERVER_IP,
    CONNECTION_WINDOW,
    SERVER_IP,
)
from utils.static_definitions import CONNECTION_DATA_NAMES, FLAG_MAP
from utils.algorithms import Algorithms

from attack_detection.ids import IDS

class PacketCapture:
    """ Packet sniffer object, used to sniff packets on the network.

    The packet capture starts the sniffer on another thread, and analyzes data coming from it.
    It the packages the data and sends it to the IDS for classification.

    Attributes:
        timeout (float): timeout in seconds for the packet capture, default INT32_MAX
        detect_interval (float): time interval to run the IDS, in milliseconds
        packet_process_queue (Queue): thread-safe queue to communicate with packet sniffer
        connection_window (deque): double-ended queue to hold connection information within the last 2 seconds
        ids (IDS): the ids object to be used
        oldest_connection (float): the oldest connection time value in the connection window.
    """
    def __init__(
        self,
        algo: Algorithms,
        timeout: float = (2**32 - 1),
        detect_interval: int = 1000,
    ):
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

        self.oldest_connection: float = -1

    # Method to start packet capture and packet analysis threads
    def run(self):
        print("Started Intrusion Detection System")
        print(
            "In another terminal use the start-attack command to start an attack to this server"
        )
        packet_sniff = threading.Thread(target=self.start_sniff)

        packet_sniff.start()
        self.analyze_packet()

    def detect_intrusion(self):
        if self.current_connection is not None:
            print("Received a new packet.")
            print("Predicting Intrusion:")
            print(self.ids.classify_connection(self.current_connection))

    def analyze_packet(self):
        prev: float = time.time()
        start: float = time.time()

        # This is where we extract packet data
        while time.time() - start < self.timeout:
            packet = self.packet_process_queue.get()
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
            self.current_connection.add_packet(trimmed_packet)

    def start_sniff(self):
        scapy.sniff(iface=IF_NAME, prn=self.queue_packet, store=0)

    def queue_packet(self, packet: scapy.packet.Packet):
        if scapy.TCP not in packet:
            return
        if scapy.IP not in packet:
            return
        if packet[scapy.IP].src != ATTACK_SERVER_IP:
            return
        if packet[scapy.IP].dst != SERVER_IP:
            return

        self.packet_process_queue.put(packet)

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

        self.current_connection = None

    def create_tcp_connection(self, trimmed_packet: TrimmedPacket) -> TCPConnection:
        data = self.calc_stats(trimmed_packet)
        count_same = 1 if data["count_same"] == 0 else data["count_same"]
        dst_host_count = 1 if data["dst_host_count"] == 0 else data["dst_host_count"]

        return TCPConnection(
            trimmed_packet.protocol,
            trimmed_packet.src_ip,
            trimmed_packet.src_port,
            trimmed_packet.dst_ip,
            trimmed_packet.dst_port,
            trimmed_packet.service,
            trimmed_packet.src_ip == trimmed_packet.dst_ip
            and trimmed_packet.src_port == trimmed_packet.dst_port,
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
            data["same_srv_count"],
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
