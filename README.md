# Flow_analysis
A real time flow analysis tool that collects transport layer protocol metadata and analyzes it for anomalies

## Installation

1. Create virtual environment:

`python3 -m venv .`

2. Source virtual environment:

`source bin/activate`

3. Install requirements:

`pip install -r requirements.txt`

4. Switch to root (for Scapy packet metadata collection):

`sudo su`

5. Source venv as root:

`source bin/activate`

6. Start webserver (as root):

`python3 webserver.py`
