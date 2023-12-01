from packet_capture.packet_capture import PacketCapture
from utils.algorithms import Algorithms

import logging
import sys
logging.getLogger("scapy").setLevel(1)
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

if __name__ == "__main__":
    PacketCapture(Algorithms.DTREE).run()