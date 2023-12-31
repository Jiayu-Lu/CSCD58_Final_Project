from utils.algorithms import Algorithms as a

# String Constants
DIVIDER = "----------------------------------------------------------------------"

# Model Constants (42)
FEATURE_COLUMNS = [
    "duration", 
    "protocol_type", 
    "service", 
    "flag", 
    "src_bytes", 
    "dst_bytes", 
    "land", 
    "wrong_fragment", 
    "urgent", 
    "hot", 
    "num_failed_logins", 
    "logged_in", 
    "num_compromised", 
    "root_shell", 
    "su_attempted", 
    "num_root", 
    "num_file_creations", 
    "num_shells", 
    "num_access_files", 
    "num_outbound_cmds", 
    "is_host_login", 
    "is_guest_login", 
    "count", 
    "srv_count", 
    "serror_rate", 
    "srv_serror_rate", 
    "rerror_rate", 
    "srv_rerror_rate", 
    "same_srv_rate", 
    "diff_srv_rate", 
    "srv_diff_host_rate", 
    "dst_host_count", 
    "dst_host_srv_count", 
    "dst_host_same_srv_rate", 
    "dst_host_diff_srv_rate", 
    "dst_host_same_src_port_rate", 
    "dst_host_srv_diff_host_rate", 
    "dst_host_serror_rate", 
    "dst_host_srv_serror_rate", 
    "dst_host_rerror_rate", 
    "dst_host_srv_rerror_rate",
    "target"
]

ATTACK_TYPES = { 
    "normal": "normal", 
    "back": "dos", 
    "buffer_overflow": "u2r", 
    "ftp_write": "r2l", 
    "guess_passwd": "r2l", 
    "imap": "r2l", 
    "ipsweep": "probe", 
    "land": "dos", 
    "loadmodule": "u2r", 
    "multihop": "r2l", 
    "neptune": "dos", 
    "nmap": "probe", 
    "perl": "u2r", 
    "phf": "r2l", 
    "pod": "dos", 
    "portsweep": "probe", 
    "rootkit": "u2r", 
    "satan": "probe", 
    "smurf": "dos", 
    "spy": "r2l", 
    "teardrop": "dos", 
    "warezclient": "r2l", 
    "warezmaster": "r2l", 
}

# Maps
PROTOCOL_MAP = {"icmp": 0, "tcp": 1, "udp": 2}

FLAG_MAP = {
    "SF": 0,
    "S0": 1,
    "REJ": 2,
    "RSTR": 3,
    "RSTO": 4,
    "SH": 5,
    "S1": 6,
    "S2": 7,
    "RSTOS0": 8,
    "S3": 9,
    "OTH": 10
    }

CONNECTION_DATA_NAMES = ["count_same",
                         "serror_count",
                         "rerror_count",
                         "same_srv_count",
                         "diff_srv_count",
                         "dst_host_count",
                         "dst_host_srv_count",
                         "dst_host_diff_srv_count",
                         "dst_host_same_src_port_count",
                         "dst_host_diff_src_port_count"]

ALGO_NAME_MAP = {
    a.GNB : "Gaussian Naive Bayes",
    a.DTREE : "Decision Tree",
    a.LR : "Logistic Regression",
    a.RF : "Random Forest",
    a.GBC : "Gradient Descent",
    a.SVC : "Support Vector Classifier"
}

STANDARD_PORTS = {
    "HTTP": [80, 8080],
    "HTTPS": [443],
    "FTP": [20, 21],
    "SSH": [22]
}