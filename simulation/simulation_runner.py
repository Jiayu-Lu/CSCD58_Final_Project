import importlib


class SimulationRunner:
    def __init__(self, attack_type):
        try:
            module = importlib.import_module(f"attack_types")
            self.attack_func = getattr(module, attack_type)
        except Exception:
            raise Exception(
                "Attack type does not exist. To create a new attack type, add a new function to simulation/attack_types.py"
            )

    def start_attack(self):
        self.attack_func()
