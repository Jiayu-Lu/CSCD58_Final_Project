import time
import pandas as pd
import logging as log
import settings as s
import utils.static_definitions as sd
 
from joblib import dump
from utils.algorithms import Algorithms as a
from utils.utils import algo_to_filepath

from sklearn.model_selection import train_test_split 
from sklearn.preprocessing import MinMaxScaler

from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression 


class IDSTrainer():
    """Represents an IDS trainer, used to train an IDS based of a variety of configs.

    The data to use during training, and any model settings can be edited in settings.py

    Attributes:
        df (pd.dataframe): used to hold the loaded data
        algo_map (dict[a]): a map of algorithms to their respective training functions
    """

    def __init__(self, training_data_path):
        self.df: pd.DataFrame = self.load_data(training_data_path)
        self.prepare_data()
        self.algo_map = {
            a.GNB: self.createGNB,
            a.DTREE: self.createDTree,
            a.RF: self.createRF,
            a.LR: self.createLogRegression,
            a.SVC: self.createSVC,
            a.GBC: self.createGBC
            }

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

    def train(self, algorithm, split=True, save=False):
        # Split dataset
        df: pd.DataFrame = self.df.drop(["target"], axis=1)

        # Extract targets
        y = df[["Attack Type"]]

        # Normalize features
        x = MinMaxScaler().fit_transform(df.drop(["Attack Type"], axis=1))

        # Split dataset
        if split:
            x_train, x_test, y_train, y_test = train_test_split(x,
                                                                y, 
                                                                test_size=s.TEST_DATA_SPLIT,
                                                                random_state=s.DATA_SPLIT_SEED)
        else:
            x_train = x
            x_test = x
            y_train = y
            y_test = y

        log.info(f"Training Model with {sd.ALGO_NAME_MAP[algorithm]}")
        model = self.algo_map[algorithm]()

        start_time: float = time.time()
        model.fit(x_train, y_train.values.ravel())

        if save:
            dump(model, algo_to_filepath(algorithm))

        log.info(sd.DIVIDER)
        log.info(f"Training time: {time.time() - start_time}")
        log.info(f"Train score is: {model.score(x_train, y_train)}") 
        log.info(f"Test score is: {model.score(x_test, y_test)}")
        log.info(sd.DIVIDER)

    def createGNB(self):
        return GaussianNB()
    
    def createDTree(self):
        return DecisionTreeClassifier(criterion=s.DTREE_CRITERION, max_depth=s.DTREE_MAX_DEPTH)
    
    def createRF(self):
        return RandomForestClassifier(n_estimators=s.RF_N_ESTIMATORS) 
    
    def createSVC(self):
        return SVC(gamma=s.SVC_GAMMA)
    
    def createLogRegression(self):
        return LogisticRegression(max_iter=s.LOG_REG_MAX_ITER) 
    
    def createGBC(self):
        return GradientBoostingClassifier(random_state=s.GBC_SEED)
