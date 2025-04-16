#!/bin/bash
BINARY_URL=
RUN_AS_USER=root
if [ "$EUID" -ne 0 ]; then
    echo "This script needs to be run as root"
    exit
fi
if [ "$#" -ne 1 ]; then
    echo "Please supply the token/SID."
    exit
fi
if [ "${#1}" -ne 32 ]; then
    echo "Invalid token length."
    exit
fi
if [ "$(which curl)" != "" ]; then
    if ! curl -s "$BINARY_URL" -o /bin/hetrixtools_agent; then
        echo "Downloading failed."
        exit
    fi
elif [ "$(which wget)" != "" ]; then
    if ! wget -q "$BINARY_URL" -O /bin/hetrixtools_agent; then
        echo "Downloading failed."
        exit
    fi
else
    echo "Please install either curl or wget. If you are getting this error but have installed at least one of them, check your PATH."
    exit
fi
chmod +x /bin/hetrixtools_agent
echo "$1" > /etc/hetrixtools_agent_token
chmod 600 /etc/hetrixtools_agent_token
chown $RUN_AS_USER /etc/hetrixtools_agent_token
echo "[Unit]
Description=HetrixTools agent (rewritten in C, unofficial)
After=network.target

[Service]
Type=simple
ExecStart=/bin/hetrixtools_agent
User=$RUN_AS_USER

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/hetrixtools_agent.service
systemctl daemon-reload
systemctl enable --now hetrixtools_agent
echo "HetrixTools agent has been installed! In around a minute you will be able to see the first statistics."