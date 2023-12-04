Module CSCD58_Final_Project.objects.tcp_connection
==================================================

Classes
-------

`TCPConnection(protocol: int, source_ip: str, source_port: int, dest_ip: str, dest_port: int, service: str, land: bool, count_same: int, serror_rate: float, rerror_rate: float, same_srv_rate: float, diff_srv_rate: float, dst_host_count: int, dst_host_srv_count: int, dst_host_diff_srv_rate: float, dst_host_same_src_port_rate: float, dst_host_diff_src_port_rate: float, same_srv_count: int)`
:   A TCP connection, holding updating information about the connection itself.
    
    This class holds information on the different properties and statistics of the connection
    itself, and connection within a 2 second window before it. When packets are added to the connection,
    it also scans the packet analyzes properties of the packet actions.

    ### Methods

    `add_packet(self, packet: trimmed_packet.TrimmedPacket)`
    :

    `analyze_action(self, data: str)`
    :

    `analyze_login(self, data: str)`
    :

    `close_connection(self)`
    :

    `get_duration(self) ‑> float`
    :