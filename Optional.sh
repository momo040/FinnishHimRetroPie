#!/bin/bash
# Script to install optional dependencies for warberry pi.

sudo git clone https://github.com/DanMcInerney/net-creds.git

sudo apt-get install onesixtyone

sudo apt-get install nikto

sudo apt-get install hydra

sudo apt-get install john

sudo apt-get install bridge-utils

sudo apt-get install w3af-console

sudo apt-get install ettercap-text-only

sudo apt-get install cryptcat

sudo apt-get install ike-scan

sudo git clone https://github.com/sqlmapproject/sqlmap.git

sudo git clone https://github.com/CoreSecurity/impacket.git

sudo git clone https://github.com/samratashok/nishang.git

sudo git clone https://github.com/SpiderLabs/Responder.git

sudo git clone https://github.com/PowerShellMafia/PowerSploit.git

sudo git clone https://github.com/offensive-security/exploit-database.git

sudo wget https://download.sysinternals.com/files/SysinternalsSuite.zip

wget https://labs.portcullis.co.uk/download/enum4linux-0.8.9.tar.gz -O /home/pi/WarBerry/Tools/

tar -zxvf enum4linux-0.8.9.tar.gz

mv enum4linux-0.8.9 enum4linux