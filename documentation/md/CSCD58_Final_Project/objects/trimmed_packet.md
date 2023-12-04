Module CSCD58_Final_Project.objects.trimmed_packet
==================================================

Classes
-------

`TrimmedPacket(packet: scapy.packet.Packet)`
:   A trimmed version of scapy.packet.Packet
    
    A trimmed version of the scapy packet, that holds less information but the relevant information
    is in a more convenient format.
    
    Attributes:
        flags (List[char]): list of TCP flags that the packet contains
        syn (bool): Whether the packet contains a SYN packet or not.
        received (float): the time the packet was received
        protocol (int): the protocol used to transmit the packet (we only accept TCP)
        size (int): length in bytes of the payload
        src_port (int): port number of the source
        dst_port (int): port number of the destination
        service (str): service of the packet (HTTP, HTTPS, etc)
        src_ip (str): ip address of the source
        dst_ip (str): ip address of the destination
        data (str): if the packet contains a payload, it is stored here