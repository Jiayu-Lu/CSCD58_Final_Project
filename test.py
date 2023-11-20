from attack_detection.train_ids import IDSTrainer
from settings import TRAINING_DATA_FULL_PATH
from utils.algorithms import Algorithms

import logging as log


if __name__ == "__main__":
    log.basicConfig(format="%(levelname)s: %(message)s")
    log.getLogger().setLevel(log.INFO)

    ids = IDSTrainer(TRAINING_DATA_FULL_PATH)
    ids.train(Algorithms.GNB, split=False, save=True)