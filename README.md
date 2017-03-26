# Ietf 98 Captive Portal Hackathon

This project was put together to track some of the work being done at the ietf 98 for the capport working group.

The following sections summarize the different parts of the project.

## dhclient_config

The dhclient_config directory contains work related to making dhclient on the user equipment detect the relevant information for interacting with the captive portal using RFC7710.

## pycapport

pycapport contains a python program to interact with the captive portal server according to the CAPPORT API. In particular, it will allow users to log in with a REST API.

##  unpv13e
This folder is a copy of the code from "UNIX Network Programming, Volume 1, Third Edition Source Code", taken from http://www.unpbook.com/unpv13e.tar.gz on March 25th, 2017.

That code has been modified to detect the icmp unreachable message indicating a captive portal, and invoke a utility (i.e. ```pycapport```) to handle the captive portal.

# Installation
_TODO_

* Run ./configure.sh in unpv13e
* make in lib
* make in icmpd

* Install python3, python3-pip, then pip3 install netifaces and argparse
