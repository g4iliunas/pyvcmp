# pyvcmp
prototype for vcmp in python. currently there are no servers for frontends, so for now it is required for users to open raw html files themselves.

# prerequisites
- `python3`
- `tor`

# how to run
## install dependencies
- `python3 -m pip install -r requirements.txt`
## setup tor service
- `sudo ./add_hiddenservice.sh`
- wait for tor to launch and configure itself...
- retrieve your hostname using `sudo ./get_address.sh`
## run
- `python3 main.py`