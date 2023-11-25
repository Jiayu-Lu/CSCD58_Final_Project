from settings import TRAINED_MODELS_FULL_PATH
from algorithms import Algorithms as a
from static_definitions import ALGO_NAME_MAP, STANDARD_PORTS
from typing import Optional

def algo_to_filepath(algo):
    filename = ALGO_NAME_MAP[algo].replace(" ", "_")
    return TRAINED_MODELS_FULL_PATH + f"/{filename}.joblib"

def port_to_service(port: int) -> Optional[str]:
    for service in STANDARD_PORTS:
        if port in STANDARD_PORTS[service]:
            return service
        
    return None