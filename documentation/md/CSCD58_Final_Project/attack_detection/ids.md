Module CSCD58_Final_Project.attack_detection.ids
================================================

Classes
-------

`IDS(algorithm: utils.algorithms.Algorithms)`
:   Class representing the IDS, responsible for loading the model, and classifying data.
    
    Attributes:
        model (sklearn): the scikit learn model loaded

    ### Methods

    `classify_connection(self, connection: objects.tcp_connection.TCPConnection)`
    :   Classifies a connection into one of the attack types.
        
        Args:
            connection: the TCPConnection object to describe the current connection
        Returns:
            A value representing the type of attack the model deems the connection is

    `load_model(self, algorithm: utils.algorithms.Algorithms)`
    :   Load the algorithm specified, sets self.model to the loaded algorithm.
        
        Args:
            algorithm: the algorithm to load
        Raises:
            FileNotFoundError: If the algorithm file is not found