import click
from click_repl import repl, exit as repl_exit
import sys
from settings import USING_ALGORITHM, SERVER_PORT
from utils.static_definitions import ALGO_NAME_MAP
from utils.algorithms import Algorithms as a
import simulation.attack_types
from simulation.simulation_runner import SimulationRunner
from packet_capture.packet_capture import PacketCapture
from server import start_server
import threading


class Settings:
    def __init__(self) -> None:
        self.detection_algorithm = USING_ALGORITHM


@click.group()
def cli():
    pass


@cli.command()
@click.pass_obj
def print_algo(context):
    """Prints out the current detection algorithm used in the simulation."""
    click.echo(
        f"{context.detection_algorithm}: {ALGO_NAME_MAP[context.detection_algorithm]}"
    )


@cli.command()
@click.argument(
    "algorithm",
    type=int,
)
@click.pass_obj
def set_algo(context, algorithm):
    """
    Sets the current detection algorithm used in the simulation.

    ALGORITHM is the number of the algorithm that is used for simulations\n
    Valid numbers are:\n
        0: Gaussian Naive Bayes\n
        1: Decision Tree Classifier\n
        2: Random Forest Classifier\n
        3: Support Vector Classifier\n
        4: Logistic Regression\n
        5: Gradient Descent\n
    """
    try:
        context.detection_algorithm = a(algorithm)
        click.echo(f"Using {ALGO_NAME_MAP[context.detection_algorithm]} Algorithm")
    except Exception as e:
        click.echo("Algorithm number is invalid.")
        click.echo("Type set-algo --help to see available algorithm numbers.")


def attack_types():
    for name in simulation.attack_types.__all__:
        click.echo(f"{name}: {getattr(simulation.attack_types, name).__doc__}")


@cli.command()
@click.pass_obj
def print_attack_types(context):
    """Prints out the available attack types that can be simulated.
    To run an attack use the attack command"""
    attack_types()


@cli.command()
@click.argument("attack_type")
@click.pass_obj
def start_attack(context, attack_type):
    """
    Starts an attack on the server

    ATTACK_TYPE: The type of attack to simulate. Type print-attack-types to see all options.
    """
    try:
        runner = SimulationRunner(attack_type)
        runner.start_attack()
    except Exception as e:
        click.echo(str(e))
        click.echo("Avaialable attack types are:\n")
        attack_types()


@cli.command()
@click.pass_obj
def start_ids(context):
    """
    Monitor the packets recieved on a server
    """
    t = threading.Thread(target=start_server)
    t.start()

    PacketCapture(context.detection_algorithm).run()


@cli.command()
def quit():
    """Exits the shell"""
    click.echo("Bye!")
    repl_exit()


@cli.command()
@click.pass_context
def start(context):
    print(
        """ __   _______       _______.     _______. __  .___  ___. 
|  | |       \     /       |    /       ||  | |   \/   | 
|  | |  .--.  |   |   (----`   |   (----`|  | |  \  /  | 
|  | |  |  |  |    \   \        \   \    |  | |  |\/|  | 
|  | |  '--'  |.----)   |   .----)   |   |  | |  |  |  | 
|__| |_______/ |_______/    |_______/    |__| |__|  |__| 
                                                         """
    )

    print(
        "An educational simulation tool to learn more about Intrusion Detection Systems (IDS)."
    )
    print("Created By: Vincent Li, Jiayu Lu and Yusuf Khan")
    print("2023")
    context.parent.obj = Settings()
    repl(context)


cli()
