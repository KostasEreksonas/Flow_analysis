# Flow_analysis
A real time flow analysis tool that collects transport layer protocol metadata and analyzes it for anomalies

# Installation

## Windows

Tested on Windows 10

1. Install prerequisites:
    1.1 Python - https://www.python.org/ftp/python/pymanager/python-manager-25.0.msix
    1.2. Git - https://github.com/git-for-windows/git/releases/download/v2.51.2.windows.1/Git-2.51.2-64-bit.exe
    1.3. Npcap - https://npcap.com/dist/npcap-1.84.exe

2. Open `cmd`.

3. Create and `cd` into folder for git repos:

`mkdir git && cd git`

4. Clone Flow_analysis repo:

`git clone https://github.com/KostasEreksonas/Flow_analysis.git`

5. Create Python virtual environment:

`python3 -m venv env`

6. Activate venv:

`cd env\Scripts && activate && cd ..\..\`

7. Install requirements:

`pip install -r requirements_windows.txt`

8. Launch webserver:

`python3 webserver.py`

9. Start interface from a web browser:

`127.0.0.1:8000`

## Linux

Tested on Arch Linux

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

7. Start interface from a web browser:

`127.0.0.1:8000`
