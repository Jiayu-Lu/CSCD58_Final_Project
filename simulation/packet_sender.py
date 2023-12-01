from scapy.all import send, IP, TCP, Raw, sr1
from settings import IF_NAME, SERVER_IP, SERVER_PORT, ATTACK_SERVER_IP, ATTACK_SERVER_PORT


def send_packet(destination_ip, source_port, destination_port, data, flags):
    ip = IP(dst=destination_ip)
    tcp = TCP(sport=source_port, dport=destination_port, flags=flags)
    raw = Raw(load=data)
    packet = ip/tcp/raw
    sr1(packet)

    print(f"Sent {flags} packet to {destination_ip}:{destination_port}")


def sim():
    destination_ip = SERVER_IP
    source_port =  ATTACK_SERVER_PORT
    destination_port = SERVER_PORT
    s_data = "start sending packet"
    a_data = "acknowledge"
    data = "Hello, this is some fake data!"
    f_data = "finish sending packet"
    number_of_packet_to_send = 1

    send_packet(destination_ip, source_port, destination_port, s_data, "S")
    send_packet(destination_ip, source_port, destination_port, a_data, "A")
    for _ in range(number_of_packet_to_send):
        send_packet(destination_ip, source_port, destination_port, data, "PA")
    send_packet(destination_ip, source_port, destination_port, f_data, "F")