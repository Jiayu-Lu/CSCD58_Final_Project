Module CSCD58_Final_Project.attack_detection.train_ids
======================================================

Classes
-------

`IDSTrainer(training_data_path)`
:   Represents an IDS trainer, used to train an IDS based of a variety of configs.
    
    The data to use during training, and any model settings can be edited in settings.py
    
    Attributes:
        df (pd.dataframe): used to hold the loaded data
        algo_map (dict[a]): a map of algorithms to their respective training functions

    ### Methods

    `createDTree(self)`
    :

    `createGBC(self)`
    :

    `createGNB(self)`
    :

    `createLogRegression(self)`
    :

    `createRF(self)`
    :

    `createSVC(self)`
    :

    `load_data(self, path: str) ‑> pandas.core.frame.DataFrame`
    :

    `prepare_data(self)`
    :

    `train(self, algorithm, split=True, save=False)`
    :