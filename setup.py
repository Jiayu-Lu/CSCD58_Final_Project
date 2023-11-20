import logging as log

from attack_detection.train_ids import IDSTrainer
from settings import TRAINING_DATA_FULL_PATH, TO_TRAIN
from utils.algorithms import Algorithms

def main():
    log.basicConfig(format="%(levelname)s: %(message)s")
    log.getLogger().setLevel(log.INFO)

    trainer = IDSTrainer(TRAINING_DATA_FULL_PATH)

    for a in Algorithms:
        if TO_TRAIN[a]:
            trainer.train(a, save=True)

if __name__ == "__main__":
    main()