#!/bin/bash
# Script to install dependencies for warberry pi.
# Note installing without pip will not work Trial1
sudo apt-get install nbtscan

sudo apt-get install python-scapy

sudo apt-get install tcpdump

sudo apt-get install nmap

sudo pip install python-nmap

sudo apt-get install python-bluez

sudo pip install optparse-pretty

sudo pip install netaddr

sudo pip install ipaddress

sudo apt-get install ppp

sudo apt-get install xprobe2

sudo apt-get install sg3-utils

sudo apt-get install netdiscover

sudo apt-get install macchanger

sudo apt-get install unzip

sudo wget http://seclists.org/nmap-de/2016/q2/att-201/clamav-exec.nse -O /usr/share/nmap/scripts/
