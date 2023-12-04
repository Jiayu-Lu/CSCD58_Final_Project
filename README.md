# CSCD58 Fall 2023 Final Project - Packet Sniffer + Intrusion Detection System

## Installation

- Download Python3
- Install requirements: `pip install -r requirements.txt`
- Run the CLI by running: `python cli.py start`
- Adjust settings in `settings.py` to your liking

## More Information

- It is often the case that if the process is forcibly interrupted, the port running the server will still be in use when running a second time. If this is the case, change the port number by changing `SERVER_PORT` in `settings.py`
- See the report (CSCD58_Project_report.pdf) for more information.
