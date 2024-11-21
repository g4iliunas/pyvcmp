#!/bin/bash

SERVICE_DIR="/var/lib/tor/vcmpservice/"

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (e.g., sudo $0)"
    exit 1
fi

sudo cat $SERVICE_DIR/hostname