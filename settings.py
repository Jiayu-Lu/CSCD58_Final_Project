import os

# Modify for your needs
TRAINING_DATA_PATH = "/attack_detection/data/kddcup.data_10_percent.gz"
DATA_SPLIT_SEED = 42
TEST_DATA_SPLIT = 0.33

TRAINED_MODEL_PATH = "/attack_detection/trained_models"

# Should not be touched
TRAINING_DATA_FULL_PATH = os.path.abspath(".") + TRAINING_DATA_PATH
TRAINED_MODELS_FULL_PATH = os.path.abspath(".") + TRAINED_MODEL_PATH
