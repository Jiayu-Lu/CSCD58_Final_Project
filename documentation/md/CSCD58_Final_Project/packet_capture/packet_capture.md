Module CSCD58_Final_Project.packet_capture.packet_capture
=========================================================

Classes
-------

`PacketCapture(algo: utils.algorithms.Algorithms, timeout: float = 4294967295, detect_interval: int = 1000)`
:   Packet sniffer object, used to sniff packets on the network.
    
    The packet capture starts the sniffer on another thread, and analyzes data coming from it.
    It the packages the data and sends it to the IDS for classification.
    
    Attributes:
        timeout (float): timeout in seconds for the packet capture, default INT32_MAX
        detect_interval (float): time interval to run the IDS, in milliseconds
        packet_process_queue (Queue): thread-safe queue to communicate with packet sniffer
        connection_window (deque): double-ended queue to hold connection information within the last 2 seconds
        ids (IDS): the ids object to be used
        oldest_connection (float): the oldest connection time value in the connection window.

    ### Methods

    `analyze_packet(self)`
    :

    `calc_stats(self, syn_packet: objects.trimmed_packet.TrimmedPacket)`
    :

    `close_current_connection(self)`
    :

    `create_tcp_connection(self, trimmed_packet: objects.trimmed_packet.TrimmedPacket) ‑> objects.tcp_connection.TCPConnection`
    :

    `detect_intrusion(self)`
    :

    `process_packet(self, packet: scapy.packet.Packet)`
    :

    `queue_packet(self, packet: scapy.packet.Packet)`
    :

    `run(self)`
    :

    `start_sniff(self)`
    :