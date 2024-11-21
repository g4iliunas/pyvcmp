#!/bin/bash

TORRC="/etc/tor/torrc"
SERVICE_DIR="/var/lib/tor/vcmpservice/"
ADDRESS="127.0.0.1"
PORT="55555"

add_hiddenservice() {
    echo "Adding hidden service to torrc..."
    echo "HiddenServiceDir $SERVICE_DIR" >> $TORRC
    echo "HiddenServicePort $PORT $ADDRESS:$PORT" >> $TORRC
    echo "Hidden service added successfully."
}

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (e.g., sudo $0)"
    exit 1
fi

add_hiddenservice

echo "Restarting Tor service..."
sudo systemctl restart tor
echo "Tor service restarted. Hidden service should now be active."