import time, scapy
from utils.static_definitions import PROTOCOL_MAP, FLAG_MAP


class TCPConnection():

    def __init__(self, protocol: str, service: str, land: bool, count_same: int, serror_rate: float,
                 rerror_rate: float, same_srv_rate: float, diff_srv_rate: float, dst_host_count: int, 
                 dst_host_srv_count: int, dst_host_diff_srv_rate: float, dst_host_same_src_port_rate: float,
                 dst_host_diff_src_port_rate: float):
        ### Object Properties ###

        # Is this connection currently active
        self.is_active: bool = True
        # Connection duration, fill out after connection closed
        self.duration: float = -1.0
        # Packets that belong to this connection
        self.packets: scapy.packet = []

        ### TCP CONNECTION FEATURES ###

        # Connection start time
        self.start_time: float = time.time()
        # Connection protocol type (TCP, UDP, ...)
        self.protocol: int = PROTOCOL_MAP[protocol]
        # 1 if host and dest is the same ip/port, 0 otherwise
        self.land: bool = land
        # Type of service (http, https, ftp, etc)
        self.service: str = service
        # Num bytes from source to dest
        self.src_bytes: int = 0
        # Num bytes from dest to source
        self.dst_bytes: int = 0
        # Num 'wrong' fragments
        self.wrong: int = 0
        # Num 'urgent' packets
        self.urgent: int = 0

        ### CONTENT FEATURES/DOMAIN KNOWLEDGE ###

        # Num 'hot' indicators (unusual/suspicious activity)
        self.hot: int = 0
        # Num failed logins (ex. ssh attempts, account logins, ...)
        self.failed_logins: int = 0
        # Logged in (if this connection can be used to login, set to True when successful)
        self.logged_in: bool = False
        # Num compromised (number of indicators of compromised, unusual access times, root, unusual changes, etc)
        self.comporimised: int = 0
        # Root shell (set to True if root privileges was obtained (ex. ssh connection))
        self.root_shell: bool = False
        # Set to 1 if 'sudo' was attempted (ex. ssh connection)
        self.su_attempted: bool = False
        # Num file creations (num file creation operations used)
        self.file_creations: int = 0
        # Num shell prompts
        self.shell_prompts: int = 0
        # Num operations on access control files (ex. .ssh files)
        self.num_access_control: int = 0
        # Num of outbound file transfers (send files to and from the server)
        self.num_outbound_ft: int = 0
        # Is hot login (if the login was made from a 'hot' indicator)
        self.is_hot_login: bool = False
        # Is the login a guest
        self.is_guest_login: bool = False

        ### TRAFFIC FEATURES, 2 SECOND WINDOW ###

        # Number of connection made within 2 seconds before this one, to the same host
        self.count_same: int = count_same

        # All measurements from below should use the connections counted by self.count

        # % of connections that had errors in the SYN stage (flag = S0, S1, S2, S3)
        self.serror_rate: float = serror_rate
        # % of connections that were rejected (flag = REG)
        self.rerror_rate: float = rerror_rate
        # % of connections that are from the same service (http, https, etc) as self.service
        self.same_srv_rate: float = same_srv_rate
        # % of connections that are from a different service (http, https, etc) as self.service
        self.diff_srv_rate: float = diff_srv_rate

        # Num connections having same dest IP in the last 2 seconds
        self.dst_host_count: int = dst_host_count

        # All measurements from below should use the connections counted by self.dst_host_count
    
        # Num connections having same dest IP + port
        self.dst_host_srv_count: int = dst_host_srv_count
        # % of connections that were with a different service as self.service
        self.dst_host_diff_srv_rate: float = dst_host_diff_srv_rate
        # % of connections that were to the same port, from self.dst_host_srv_count
        self.dst_host_same_src_port_rate: float = dst_host_same_src_port_rate
        # % of connections that were to different ports, from self.dst_host_srv_count
        self.dst_host_diff_src_port_rate: float = dst_host_diff_src_port_rate


    def get_duration(self) -> float:
        return self.duration if not self.is_active else time.time() - self.start_time
    
    def close_connection(self):
        self.is_active = False
        self.duration = time.time() - self.start_time

    def add_packet(self, packet: scapy.packet):
        self.packets.append(packet)




