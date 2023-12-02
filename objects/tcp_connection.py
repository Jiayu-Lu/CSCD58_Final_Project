import time
import utils.payload_data as pd

from trimmed_packet import TrimmedPacket
from utils.static_definitions import PROTOCOL_MAP, FLAG_MAP
from settings import LOGIN_THRESH, TRANSFER_THRESH



class TCPConnection():
    def __init__(self, protocol: int, source_ip: str, source_port: int, dest_ip: str, dest_port: int,
                 service: str, land: bool, count_same: int, serror_rate: float,
                 rerror_rate: float, same_srv_rate: float, diff_srv_rate: float, dst_host_count: int,
                 dst_host_srv_count: int, dst_host_diff_srv_rate: float, dst_host_same_src_port_rate: float,
                 dst_host_diff_src_port_rate: float, same_srv_count: int):
        ### Object Properties ###
    
        # Connection start time
        self.start_time: float = time.time()
        # Is this connection currently active
        self.is_active: bool = True
        # Connection duration, fill out after connection closed
        self.duration: float = -1.0
        # Connection closing time
        self.end_time: float = -1.0
        # Packets that belong to this connection
        self.packets: TrimmedPacket = []
        # IP the connection is coming from
        self.source_ip: str = source_ip
        # Port the connection is coming from
        self.source_port: int = source_port
        # IP the connection is going to
        self.dest_ip: str = dest_ip
        # Port the connection is going to
        self.dest_port: int = dest_port
    
        ### TCP CONNECTION FEATURES ###
    
        # Packet flag
        self.flag: int = 0
        # Connection protocol type (TCP, UDP, ...)
        self.protocol: int = protocol
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
        # flag to indicate if the SYN had an ACK in return
        self.ack: bool = False
        # flag to indicate RST was received
        self.rst: bool = False
        # flag to indicate FIN was received
        self.fin: bool = False
    
        ### CONTENT FEATURES/DOMAIN KNOWLEDGE ###
    
        # Num 'hot' indicators (unusual/suspicious activity)
        self.hot: int = 0
        # Num failed logins (ex. ssh attempts, account logins, ...)
        self.failed_logins: int = 0
        # Logged in (if this connection can be used to login, set to True when successful)
        self.logged_in: bool = False
        # Num compromised (number of indicators of compromised, unusual access times, root, unusual changes, etc)
        self.compromised: int = 0
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
        # Is host login
        self.is_host_login: bool = False
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
        # Number of connections with the same service
        self.same_srv_count: int = same_srv_count
        # % of connections that are from the same service (http, https, etc) as self.service
        self.same_srv_rate: float = same_srv_rate
        # % of connections that are from a different service (http, https, etc) as self.service
        self.diff_srv_rate: float = diff_srv_rate
    
        # Num connections having same dest IP in the last 2 seconds
        self.dst_host_count: int = dst_host_count
    
        # All measurements from below should use the connections counted by self.dst_host_count
    
        # Num connections having same IP + same service
        self.dst_host_srv_count: int = dst_host_srv_count
        # % of connections that were with a different service as self.service
        self.dst_host_diff_srv_rate: float = dst_host_diff_srv_rate
        # % of connections that were to the same port, from self.dst_host_srv_count
        self.dst_host_same_src_port_rate: float = dst_host_same_src_port_rate
        # % of connections that were to different ports, from self.dst_host_srv_count
        self.dst_host_diff_src_port_rate: float = dst_host_diff_src_port_rate
        
    def __str__(self):
        msg = f"TCP connection starts at: {self.start_time}\n"
        msg += f"\tduration: {self.get_duration()}\n"
        msg += f"\tis active: {self.is_active}\n"
        msg += f"\tnumber of packets captured: {len(self.packets)}\n"
        return msg

    def get_duration(self) -> float:
        return self.duration if not self.is_active else time.time() - self.start_time
    
    def close_connection(self):
        self.is_active = False
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time

        if self.ack and self.fin:
            self.flag = FLAG_MAP["SF"]
        elif self.ack and self.rst:
            self.flag = FLAG_MAP["RSTOS0"]
        elif self.rst:
            self.flag = FLAG_MAP["REJ"]
        else:
            self.flag = FLAG_MAP["S0"]


    def add_packet(self, packet: TrimmedPacket):
        # add packets to list
        self.packets.append(packet)

        # Check flags
        if "R" in packet.flags:
            self.rst = True
        if "A" in packet.flags:
            self.ack = True
        if "U" in packet.flags:
            self.urgent += 1

        # Add data size
        if packet.src_ip == self.source_ip:
            self.src_bytes += packet.size
        else:
            self.dst_bytes += packet.size

        #print("CONNECTION_STATS")
        #print(self)

        if packet.data is not None:
            print(packet.data)
            if pd.LOGIN_KEYWORD in packet.data:
                self.analyze_login(packet.data)
            else:
                self.analyze_action(packet.data)

        # Need to setup some sort of domain knowledge

    def analyze_action(self, data: str):
        if pd.Actions.SUDO.name in data:
            self.su_attempted = True
        if pd.Actions.OPEN_SHELL.name in data:
            self.shell_prompts += 1
        if pd.Actions.CLOSE_SHELL.name in data:
            self.shell_prompts = 0 if self.shell_prompts == 0 else self.shell_prompts - 1
        if pd.Actions.CREATE_FILE.name in data:
            self.file_creations += 1
        if pd.Actions.FILE_TRANSFER.name in data:
            self.num_outbound_ft += 1
            if self.num_outbound_ft > TRANSFER_THRESH:
                self.compromised += 1
                self.hot += 1
        if pd.Actions.ACCESS_CONTROL_FILE.name in data:
            self.num_access_control += 1
        if pd.Actions.ACCESS_RESTRICTED_RES.name in data:
            self.hot += 1
        if pd.Actions.MODIFY_RESTRICTED_RES.name in data:
            self.hot += 1

    def analyze_login(self, data: str):
        if pd.LoginStatus.FAILED.name in data:
            self.failed_logins += 1
            if self.failed_logins > LOGIN_THRESH:
                self.hot += 1
        else:
            self.logged_in = True
            if self.failed_logins > LOGIN_THRESH:
                self.compromised += 1
            if pd.LoginStatus.ROOT.name in data:
                self.root_shell = True
                self.compromised += 1
            if pd.LoginStatus.HOST.name in data:
                self.is_host_login = True
            else:
                self.is_guest_login = True

