import time
import pandas as pd
import logging as log
 
from joblib import load, dump
from . import static_definitions as sd
from utils.algorithms import Algorithms as a
from settings import TEST_DATA_SPLIT, DATA_SPLIT_SEED, TRAINED_MODELS_FULL_PATH

from sklearn.model_selection import train_test_split 
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score 

from sklearn.naive_bayes import GaussianNB 


class IDSTrainer():

    def __init__(self, training_data):
        self.df: pd.DataFrame = self.load_data(training_data)
        self.prepare_data()
        self.algo_map = {a.GNB : self.trainGNB}

    def load_data(self, path: str) -> pd.DataFrame:
        df: pd.DataFrame = pd.read_csv(path, names = sd.FEATURE_COLUMNS)
        df["Attack Type"] = df.target.apply(lambda x: sd.ATTACK_TYPES[x[:-1]])
        return df
    
    def prepare_data(self):
        self.df = self.df.dropna(axis=1)

        # Remove this columns as they have very high correlation (~0.98) with other columns
        self.df.drop("num_root", axis=1, inplace=True) 
        self.df.drop("srv_serror_rate", axis=1, inplace=True) 
        self.df.drop("srv_rerror_rate", axis=1, inplace=True) 
        self.df.drop("dst_host_srv_serror_rate", axis=1, inplace=True) 
        self.df.drop("dst_host_serror_rate", axis=1, inplace=True) 
        self.df.drop("dst_host_rerror_rate", axis=1, inplace=True) 
        self.df.drop("dst_host_srv_rerror_rate", axis=1, inplace=True) 
        self.df.drop("dst_host_same_srv_rate", axis=1, inplace=True)

        # service feature unneeded
        self.df.drop("service", axis=1, inplace=True)

        # Map catagories to numbers
        self.df["protocol_type"] = self.df["protocol_type"].map(sd.PROTOCOL_MAP)
        self.df["flag"] = self.df["flag"].map(sd.FLAG_MAP)

    def train(self, algorithm, save=False):
        # Split dataset
        df: pd.DataFrame = self.df.drop(["target"], axis=1)

        # Extract targets
        y = df[["Attack Type"]]

        # Normalize features
        x = MinMaxScaler().fit_transform(df.drop(["Attack Type"], axis=1))

        # Split dataset
        x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=TEST_DATA_SPLIT, random_state=DATA_SPLIT_SEED) 

        log.info(f"Training Model with {sd.ALGO_NAME_MAP[algorithm]}")
        start_time: float = time.time()
        model = self.algo_map[algorithm](x_train, y_train)
        log.info(f"Training time: {time.time() - start_time}")

        log.info(f"Train score is: {model.score(x_train, y_train)}") 
        log.info(f"Test score is: {model.score(x_test, y_test)}") 

        if save:
            filename = sd.ALGO_NAME_MAP[algorithm].replace(" ", "_")
            dump(model, TRAINED_MODELS_FULL_PATH + f"/{filename}.joblib")

    def trainGNB(self, x: pd.DataFrame, y: pd.DataFrame):
        model: GaussianNB = GaussianNB()
        model.fit(x, y.values.ravel())
        return model