import os
import pandas as pd

from joblib import load
from utils.algorithms import Algorithms
from utils.utils import algo_to_filepath, ALGO_NAME_MAP
from objects.tcp_connection import TCPConnection


class IDS:
    """ Class representing the IDS, responsible for loading the model, and classifying data.

        Attributes:
            model (sklearn): the scikit learn model loaded
    """
    def __init__(self, algorithm: Algorithms):
        self.model = self.load_model(algorithm)
        print(f"Using algorithm: {ALGO_NAME_MAP[algorithm]}")

    def load_model(self, algorithm: Algorithms):
        """Load the algorithm specified, sets self.model to the loaded algorithm.

        Args:
            algorithm: the algorithm to load
        Raises:
            FileNotFoundError: If the algorithm file is not found
        
        """
        filepath = algo_to_filepath(algorithm)

        if os.path.exists(filepath):
            return load(filepath)
        else:
            raise FileNotFoundError("Model with that algorithm is not trained yet.")

    def classify_connection(self, connection: TCPConnection):
        """ Classifies a connection into one of the attack types.

        Args:
            connection: the TCPConnection object to describe the current connection
        Returns:
            A value representing the type of attack the model deems the connection is
        """
        data = []

        if connection is not None:
            data.append(connection.get_duration())
            data.append(connection.protocol)
            data.append(connection.flag)
            data.append(connection.src_bytes)
            data.append(connection.dst_bytes)
            data.append(int(connection.land))
            data.append(connection.wrong)
            data.append(connection.urgent)
            data.append(connection.hot)
            data.append(connection.failed_logins)
            data.append(connection.logged_in)
            data.append(connection.compromised)
            data.append(int(connection.root_shell))
            data.append(int(connection.su_attempted))
            data.append(connection.file_creations)
            data.append(connection.shell_prompts)
            data.append(connection.num_access_control)
            data.append(connection.num_outbound_ft)
            data.append(int(connection.is_host_login))
            data.append(int(connection.is_guest_login))
            data.append(connection.count_same)
            data.append(connection.same_srv_count)
            data.append(connection.serror_rate)
            data.append(connection.rerror_rate)
            data.append(connection.same_srv_count)
            data.append(connection.diff_srv_rate)
            data.append(0)  # srv_diff_host_rate
            data.append(connection.dst_host_count)
            data.append(connection.dst_host_srv_count)
            data.append(connection.dst_host_diff_srv_rate)
            data.append(connection.dst_host_same_src_port_rate)
            data.append(0)  # dst_host_srv_diff_host_rate

            arr = pd.array(data).reshape(1, -1)

            return self.model.predict(arr)[0]
