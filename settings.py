import os
from utils.algorithms import Algorithms as a

# Modify for your needs
TRAINING_DATA_NAME = "kddcup.data_10_percent.gz"
TRAINING_DATA_PATH = f"/attack_detection/data/{TRAINING_DATA_NAME}"
DATA_SPLIT_SEED = 42
TEST_DATA_SPLIT = 0.33

TRAINED_MODEL_PATH = "/attack_detection/trained_models"

# Packet sniffer settings
IF_NAME = "lo0"

SERVER_IP = "127.0.0.1"
SERVER_PORT = 8081
ATTACK_SERVER_IP = "127.0.0.1"
ATTACK_SERVER_PORT = 4999

USING_ALGORITHM = a.LR

# Select what models to train, set what you want to train to 'True'
TO_TRAIN = {
    a.GBC: True,
    a.DTREE: True,
    a.LR: True,
    a.RF: True,
    a.SVC: True,
    a.GNB: True
}

# Domain Knowledge Settings
LOGIN_THRESH = 5
TRANSFER_THRESH = 5

# Should not be touched
TRAINING_DATA_FULL_PATH = os.path.abspath(".") + TRAINING_DATA_PATH
TRAINED_MODELS_FULL_PATH = os.path.abspath(".") + TRAINED_MODEL_PATH
FILTER_STR = f"src host {ATTACK_SERVER_IP} and src port {ATTACK_SERVER_PORT} and dst host {SERVER_IP} and dst port {SERVER_PORT}"

# Model settings (don't touch unless needed)
DTREE_CRITERION = "entropy"
DTREE_MAX_DEPTH = 4
RF_N_ESTIMATORS = 30
SVC_GAMMA = "scale"
LOG_REG_MAX_ITER = 1200000
GBC_SEED = 0
CONNECTION_WINDOW = 2