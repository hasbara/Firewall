#!/bin/bash

#
# PREPARE IPTABLES
#

#flush rules and chains
iptables -t filter -F
iptables -t filter -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X

#
# DEFAULT CHAIN POLICY
#

#prerouting
iptables -t raw -P PREROUTING ACCEPT
iptables -t mangle -P PREROUTING ACCEPT
iptables -t nat -P PREROUTING ACCEPT

#input
iptables -t mangle -P INPUT ACCEPT
iptables -t filter -P INPUT ACCEPT

#forward
iptables -t mangle -P FORWARD ACCEPT
iptables -t filter -P FORWARD ACCEPT

#output
iptables -t raw -P OUTPUT ACCEPT
iptables -t mangle -P OUTPUT ACCEPT
iptables -t nat -P OUTPUT ACCEPT
iptables -t filter -P OUTPUT ACCEPT

#postrouting
iptables -t mangle -P POSTROUTING ACCEPT
iptables -t nat -P POSTROUTING ACCEPT


