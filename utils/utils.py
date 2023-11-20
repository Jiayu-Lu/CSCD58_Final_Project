from settings import TRAINED_MODELS_FULL_PATH
from algorithms import Algorithms as a
from static_definitions import ALGO_NAME_MAP

def algo_to_filepath(algo):
    filename = ALGO_NAME_MAP[algo].replace(" ", "_")
    return TRAINED_MODELS_FULL_PATH + f"/{filename}.joblib"