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

# protocol
## note
- every packet of vcmp should begin with a header as follows: vcmp magic string, vcmp version, packet type
## authorizing into vcmp
1. peer connects to host peer
2. peer sends `VCMPPacket.HANDSHAKE` packet 
3. if host peer approves, it sends back a `VCMPPacket.HANDSHAKE_ACK`

4. peer begins a pubkey transaction by sending a `VCMPPacket.PUBKEY_BEGIN`
5. host peer sends its rsa public key: `VCMPPacket.PUBKEY`
6. peer sends back its rsa public key: `VCMPPacket.PUBKEY_ACK`
7. host peer ends the transaction by sending a `VCMPPacket.PUBKEY_END`

8. peer begins an identification transaction by sending a `VCMPOpcode.IDENTIFY_BEGIN`
9. host peer sends its information (username, ....): `VCMPOpcode.IDENTIFY`
10. peer sends back its information (username, TOR hidden service address....): `VCMPOpcode.IDENTIFY_ACK`
11. host peer ends the transaction by sending a `VCMPOpcode.IDENTIFY_END`