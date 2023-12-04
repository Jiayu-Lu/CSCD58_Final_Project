from attack_detection.train_ids import IDSTrainer
from settings import TRAINING_DATA_FULL_PATH
from utils.algorithms import Algorithms

import logging as log

from scapy.all import *

from objects.trimmed_packet import TrimmedPacket
from packet_capture.packet_capture import PacketCapture

from simulation.attack_types import sim
from simulation.simulation_runner import SimulationRunner


def test(packet):
    if TCP not in packet:
        return
    if IP not in packet:
        return
    if "S" not in packet[TCP].flags and Raw not in packet:
        return
    t = TrimmedPacket(packet)
    if t.syn:
        print(t)


if __name__ == "__main__":
    # log.basicConfig(format="%(levelname)s: %(message)s")
    # log.getLogger().setLevel(log.INFO)

    # ids = IDSTrainer(TRAINING_DATA_FULL_PATH)
    # ids.train(Algorithms.GNB, split=False, save=True)
    # runner = SimulationRunner("port_scan")
    # runner.start_attack()
    sim()
