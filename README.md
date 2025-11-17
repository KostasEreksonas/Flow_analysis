# Flow_analysis
A real time flow analysis tool that collects transport layer protocol metadata and analyzes it for anomalies

# Installation

## Windows

Tested on Windows 10

1. Install prerequisite packages:
    * Python - https://www.python.org/ftp/python/pymanager/python-manager-25.0.msix
    * 1.2. Git - https://github.com/git-for-windows/git/releases/download/v2.51.2.windows.1/Git-2.51.2-64-bit.exe
    * 1.3. Npcap - https://npcap.com/dist/npcap-1.84.exe

2. Open Powershell.

3. Create and change into folder for git repos:

`cd .\Documents\ && mkdir git && cd .\git\`

4. Clone Flow_analysis repo:

`git clone https://github.com/KostasEreksonas/Flow_analysis.git`

5. Install `uv` package manager:

`powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"`

6. When finished, exit Powershell session and open a new one.

7. Change into `Flow_analysis` repo:

`cd .\Documents\git\Flow_analysis`

8. Run `webserver.py`:

`uv run webserver.py`

On first run, `uv` will install required packages

9. Start interface from a web browser:

`127.0.0.1:8000`

## Linux

Tested on Arch Linux

1. Check if `uv` is installed:

`uv --version`

2. Run `webserver.py` as root:

`sudo uv run webserver.py`

On first run, `uv` will install required dependencies

3. Start interface from a web browser:

`127.0.0.1:8000`
