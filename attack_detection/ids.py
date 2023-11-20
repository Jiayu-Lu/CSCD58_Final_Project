import os
import pandas as pd

from joblib import load
from utils.utils import algo_to_filepath

class IDS():
    
    def __init__(self, algorithm):
        self.model = self.load_model(algorithm)

    def load_model(self, algorithm):
        filepath = algo_to_filepath(algorithm)

        if os.path.exists(filepath):
            self.model = load(algo_to_filepath(algorithm))
        else:
            raise FileNotFoundError("Model with that algorithm is not trained yet.")
    
    def classify_test(self, test):
        return self.model.predict(test)

    def classify_packet(self):
        pass



