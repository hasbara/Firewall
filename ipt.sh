#!/bin/bash

#NOTE: nf_conntrack_ftp module should be mentioned in /etc/modules to load at boot time to make passive FTP work
#NOTE: with kernel 4.7 you need "net.netfilter.nf_conntrack_helper = 1" in sysctl.conf to continue things like PASV FTP

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

#statefull chains
iptables -N new_out
iptables -N new_in
iptables -N related_out
iptables -N related_in
iptables -N established_out
iptables -N established_in

#logging chains by level
iptables -N log3
iptables -N log4
iptables -N log6

#
# DEFAULT CHAIN POLICY
#

#prerouting
iptables -t raw -P PREROUTING ACCEPT
iptables -t mangle -P PREROUTING ACCEPT
iptables -t nat -P PREROUTING ACCEPT

#input
iptables -t mangle -P INPUT ACCEPT
iptables -t filter -P INPUT DROP

#forward
iptables -t mangle -P FORWARD ACCEPT
iptables -t filter -P FORWARD DROP

#output
iptables -t raw -P OUTPUT ACCEPT
iptables -t mangle -P OUTPUT ACCEPT
iptables -t nat -P OUTPUT ACCEPT
iptables -t filter -P OUTPUT DROP

#postrouting
iptables -t mangle -P POSTROUTING ACCEPT
iptables -t nat -P POSTROUTING ACCEPT


#loopback
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

#
# STATEFULL FILTERING
#

#established connections
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j established_out
iptables -A INPUT -m conntrack --ctstate ESTABLISHED -j established_in

#related connections
iptables -A OUTPUT -m conntrack --ctstate RELATED -j related_out
iptables -A INPUT -m conntrack --ctstate RELATED -j related_in

#new connections
iptables -A OUTPUT -m conntrack --ctstate NEW -j new_out
iptables -A INPUT -m conntrack --ctstate NEW -j new_in

#log specific connections
iptables -A log6 -j LOG --log-level notice --log-prefix "notice "
iptables -A log6 -j ACCEPT

#log invalid connections
iptables -A OUTPUT -m conntrack --ctstate INVALID -j log4
iptables -A INPUT -m conntrack --ctstate INVALID -j log4
iptables -A log4 -j LOG --log-level notice --log-prefix "invalid "
iptables -A log4 -j DROP

#log untracked connections
iptables -A OUTPUT -m conntrack --ctstate UNTRACKED -j log3
iptables -A INPUT -m conntrack --ctstate UNTRACKED -j log3
iptables -A log3 -j LOG --log-level notice --log-prefix "untracked "
iptables -A log3 -j DROP

#log connections not processed by statefull filter above
iptables -A OUTPUT -j LOG --log-level notice  --log-prefix "critical_out "
iptables -A INPUT -j LOG --log-level notice --log-prefix "critical_in "

#
# FORWARDING AND NAT
#

#wirtual wifi packet forwarding
#iptables -A FORWARD -i wlan1 -o wlan0 -s 172.16.1.1/24 -j ACCEPT
#iptables -A FORWARD -o wlan1 -i wlan0 -d 172.16.1.1/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

iptables -A FORWARD -j LOG --log-level notice  --log-prefix "critical_forward "

#iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE

#
# ESTABLISHED OUTBOUND CONNECTIONS
#

#dhcp server (used by virtual wifi)
#iptables -A established_out -p udp --sport 67 --dport 68 -j ACCEPT

#dhcp client
#iptables -A established_out -p udp --sport 68 --dport 67 -j ACCEPT

#dns server (used by virtual wifi)
#iptables -A established_out -p udp --sport 53 -d 172.16.1.1/24 -j ACCEPT

#dns client (probably server uses too)
iptables -A established_out -p udp --dport 53 -j ACCEPT
#iptables -A established_out -p tcp --dport 53 -j ACCEPT

#dnscrypt (fetch server certificates and DNS)
iptables -A established_out -p udp --dport 443 -d 185.60.147.77 -j ACCEPT

#http/https client
iptables -A established_out -p tcp -m multiport --destination-ports 80,443 -j ACCEPT

#rtmp/e Flash Media Server
#iptables -A established_out -p tcp --dport 1935 -j ACCEPT

#ntp client/server (ntpq)
#iptables -A established_out -p udp --sport 123 --dport 123 -j ACCEPT

#ftp client (active and passive)
iptables -A established_out -p tcp --sport 1024: --dport 21 -j ACCEPT

#ftp client (active)
#iptables -A established_out -p tcp --sport 1024: --dport 20 -j ACCEPT

#ftp client (passive)
iptables -A established_out -p tcp --sport 1024: --dport 1024: -m helper --helper ftp -j ACCEPT

#ftps client
#iptables -A established_out -p tcp --sport 1024: --dport 990 -j ACCEPT

#ssh client/server, sftp client (used by git for ssh and filezilla sftp)
iptables -A established_out -p tcp --dport 22 -j ACCEPT

#mail client
#iptables -A established_out -p tcp --dport 995 -j ACCEPT #pop3s
#iptables -A established_out -p tcp --dport 465 -j ACCEPT #smtps
#iptables -A established_out -p tcp --dport 993 -j ACCEPT #imaps

#git client
iptables -A established_out -p tcp --dport 9418 -j ACCEPT

#bitcoin client
#iptables -A established_out -p tcp --dport 8333 -j ACCEPT

#bitmessage client (allow all not needed)
#iptables -A established_out -p tcp --dport 8444 -j ACCEPT

#chess (fics)
#iptables -A established_out -p tcp --dport 5000 -j ACCEPT

#tor (9030 not used but mentioned) official site  https://www.torproject.org/docs/faq.html.en#OutboundPorts
iptables -A established_out -p tcp --dport 9001 -j ACCEPT
#iptables -A established_out -p tcp --dport 9030 -j ACCEPT

#tor (default tor ports not mentioned on official site)  https://www.wilderssecurity.com/threads/setting-up-tor-proxomitron-sockscap.55748/
#iptables -A established_out -p tcp -m multiport --dports 9001:9004 -j ACCEPT
#iptables -A established_out -p tcp -m multiport --dports 9030:9033 -j log6
#iptables -A established_out -p tcp --dport 9100 -j log6

#ping
iptables -A established_out -p icmp --icmp-type 8 -j ACCEPT

#log
iptables -A established_out -j LOG --log-level notice --log-prefix "drop-est-out "
iptables -A established_out -j DROP

#
# ESTABLISHED INBOUND CONNECTIONS
#

#dhcp server (userd by virtual wifi)
#iptables -A established_in -p udp --sport 68 --dport 67 -j ACCEPT

#dhcp client
#iptables -A established_in -p udp --sport 67 --dport 68 -j ACCEPT

#dns server (used by virtual wifi)
#iptables -A established_in -p udp -s 172.16.1.1/24 --dport 53 -j ACCEPT

#dns client (porbably server uses too)
iptables -A established_in -p udp --sport 53 -j ACCEPT
#iptables -A established_in -p tcp --sport 53 -j ACCEPT

#dnscrypt (fetch server certificates and DNS)
iptables -A established_in -p udp --sport 443 -s 185.60.147.77 -j ACCEPT

#http/https client
iptables -A established_in -p tcp -m multiport --source-ports 80,443 -j ACCEPT

#rtmp/e Flash Media Server
#iptables -A established_in -p tcp --sport 1935 -j ACCEPT

#ntp client/server (ntpq)
#iptables -A established_in -p udp --sport 123 --dport 123 -j ACCEPT

#ntp client (systemd-timesyncd)
#https://wiki.archlinux.org/index.php/systemd-timesyncd
iptables -A established_in -p udp --sport 123 -j ACCEPT

#ftp client (active and passive)
iptables -A established_in -p tcp --sport 21 --dport 1024: -j ACCEPT

#ftp client (active)
#iptables -A established_in -p tcp --sport 20 --dport 1024: -j ACCEPT

#ftp client (passive)
iptables -A established_in -p tcp --sport 1024: --dport 1024: -m helper --helper ftp -j ACCEPT

#ftps client
#iptables -A established_in -p tcp --sport 990 --dport 1024: -j ACCEPT

#ssh client/server, sftp client(used by git for ssh and filezilla sftp)
iptables -A established_in -p tcp --sport 22 -j ACCEPT

#mail client
#iptables -A established_in -p tcp --sport 995 -j ACCEPT #pop3s
#iptables -A established_in -p tcp --sport 465 -j ACCEPT #smtps
#iptables -A established_in -p tcp --sport 993 -j ACCEPT #imaps

#git client
iptables -A established_in -p tcp --sport 9418 -j ACCEPT

#bitcoin client
#iptables -A established_in -p tcp --sport 8333 -j ACCEPT

#bitmessage client
#iptables -A established_in -p tcp --sport 8444 -j ACCEPT

#chess (fics)
#iptables -A established_in -p tcp --sport 5000 -j ACCEPT

#tor (9030 not used but mentioned) official site  https://www.torproject.org/docs/faq.html.en#OutboundPorts
iptables -A established_in -p tcp --sport 9001 -j ACCEPT
#iptables -A established_in -p tcp --dport 9030 -j ACCEPT

#tor (default tor ports not mentioned on official site)  https://www.wilderssecurity.com/threads/setting-up-tor-proxomitron-sockscap.55748/
#iptables -A established_in -p tcp -m multiport --dports 9001:9004 -j log6
#iptables -A established_in -p tcp -m multiport --dports 9030:9033 -j log6
#iptables -A established_in -p tcp --dport 9100 -j log6

#reply to ping
iptables -A established_in -p icmp --icmp-type 0 -j ACCEPT
iptables -A established_in -p icmp --icmp-type 3 -j ACCEPT
iptables -A established_in -p icmp --icmp-type 11 -j ACCEPT

#log
iptables -A established_in -j LOG --log-level notice --log-prefix "drop-est-in "
iptables -A established_in -j DROP

#
# RELATED OUTBOUND CONNECTIONS
#

#ftp client (passive)
iptables -A related_out -p tcp --sport 1024: --dport 1024: -m helper --helper ftp -j ACCEPT

#reply to dns
iptables -A related_out -p icmp --icmp-type 3 -j ACCEPT

#multicast/broadcast
iptables -A related_out -m pkttype --pkt-type broadcast -j ACCEPT
iptables -A related_out -m pkttype --pkt-type multicast -j ACCEPT

#log
iptables -A related_out -j LOG --log-level notice --log-prefix "drop-rel-out "
iptables -A related_out -j DROP

#
# RELATED INBOUND CONNECTIONS
#

#ftp client (active)
iptables -A related_in -p tcp --sport 20 --dport 1024: -m helper --helper ftp -j ACCEPT

#traceroute reply
iptables -A related_in -p icmp --icmp-type 0 -j ACCEPT
iptables -A related_in -p icmp --icmp-type 3 -j ACCEPT
iptables -A related_in -p icmp --icmp-type 11 -j ACCEPT

#multicast/broadcast
iptables -A related_in -m pkttype --pkt-type multicast -j ACCEPT
iptables -A related_in -m pkttype --pkt-type broadcast -j ACCEPT

#log
iptables -A related_in -j LOG --log-level notice --log-prefix "drop-rel-in "
iptables -A related_in -j DROP

#
# NEW OUTBOUND CONNECTIONS
#

#dhcp client
#iptables -A new_out -p udp --sport 68 --dport 67 -j ACCEPT

#dns (should be used as client only)
iptables -A new_out -p udp --dport 53 -j ACCEPT
#iptables -A new_out -p tcp --dport 53 -j ACCEPT

#dnscrypt (fetch server certificates and DNS)
iptables -A new_out -p udp --dport 443 -d 185.60.147.77 -j ACCEPT

#http/https client (also used by tor)
iptables -A new_out -p tcp -m multiport --destination-ports 80,443 -j ACCEPT

#rtmp/e Flash Media Server
#iptables -A new_out -p tcp --dport 1935 -j ACCEPT

#ntp client/server (ntpd)
#iptables -A new_out -p udp --sport 123 --dport 123 -j ACCEPT

#ntp client (systemd-timesyncd)
#https://wiki.archlinux.org/index.php/systemd-timesyncd
iptables -A new_out -p udp --dport 123 -j ACCEPT

#ftp client (active and pasive)
iptables -A new_out -p tcp --sport 1024: --dport 21 -j ACCEPT

#ftps client
#iptables -A new_out -p tcp --sport 1024: --dport 990 -j ACCEPT

#ssh/sftp client (used by git for ssh and filezilla sftp)
iptables -A new_out -p tcp --dport 22 -j ACCEPT

#mail client
#iptables -A new_out -p tcp --dport 110 -j log6
#iptables -A new_out -p tcp --dport 995 -j log6 #pop3s
#iptables -A new_out -p tcp --dport 25 -j log6 #pop3
#iptables -A new_out -p tcp --dport 587 -j log6
#iptables -A new_out -p tcp --dport 465 -j ACCEPT #smtps client
#iptables -A new_out -p tcp --dport 143 -j log6
#iptables -A new_out -p tcp --dport 993 -j ACCEPT #imaps client

#git client
iptables -A new_out -p tcp --dport 9418 -j ACCEPT

#chess (fics), timeseal needs no open port (see netstat)
#iptables -A new_out -p tcp --dport 5000 -j ACCEPT

#tor (9030 not needed but mentioned) official site  https://www.torproject.org/docs/faq.html.en#OutboundPorts
iptables -A new_out -p tcp --dport 9001 -j ACCEPT
#iptables -A new_out -p tcp --dport 9030 -j ACCEPT

#tor (default tor ports not mentioned on official site)  https://www.wilderssecurity.com/threads/setting-up-tor-proxomitron-sockscap.55748/
#iptables -A new_out -p tcp -m multiport --dports 9001:9004 -j ACCEPT
#iptables -A new_out -p tcp -m multiport --dports 9030:9033 -j ACCEPT
#iptables -A new_out -p tcp --dport 9100 -j ACCEPT

#bitcoin client
#iptables -A new_out -p tcp --dport 8333 -j ACCEPT

#bitmessage client
#iptables -A new_out -p tcp --dport 8444 -j ACCEPT

#ping and traceroute
iptables -A new_out -p icmp --icmp-type 8 -j ACCEPT
iptables -A new_out -p udp --dport 33434:33523 -j ACCEPT

#multicast/broadcast
iptables -A new_out -m pkttype --pkt-type broadcast -j ACCEPT
iptables -A new_out -m pkttype --pkt-type multicast -j ACCEPT

#log
iptables -A new_out -j LOG --log-level notice --log-prefix "drop-new-out "
iptables -A new_out -j DROP

#
# NEW INBOUND CONNECTIONS
#

#dhcp server (used for virtual wifi)
#iptables -A new_in -p udp --sport 68 --dport 67 -j ACCEPT

#dhcp client (broadcast offer - test rule since ISC use raw packets)
#iptables -A new_in -p udp --sport 67 --dport 68 -d 255.255.255.255 -j ACCEPT

#dns server (used for vitrual wifi)
#iptables -A new_in -p udp -s 172.16.1.1/24 --dport 53 -j ACCEPT

#bitcoin (node, port forward needed)
#iptables -A new_in -p tcp --dport 8333 -j ACCEPT

#bitmessage (node, port forward needed)
#iptables -A new_in -p tcp --dport 8444 -j ACCEPT

#multicast/broadcast
iptables -A new_in -m pkttype --pkt-type multicast -j ACCEPT
iptables -A new_in -m pkttype --pkt-type broadcast -j ACCEPT

#log
iptables -A new_in -j LOG --log-level notice --log-prefix "drop-new-in "
iptables -A new_in -j DROP


#DESTINATION PORT INFO
#dns 53
#http 80
#https 443
#ftp 21
#ntp 123
#pop3 110
#pop3s 995
#smtp (MTA) 25
#smtps (MSA) 587
#smtps (MTA/MSA) 465
#imap 143
#imaps 993
#ssh/sftp 22
#ftps 990
#git (git protocol - for github is either ssh or https) 9418
#chess (fics) 5000
#tor 80, 443, 9001, and 9030 and also others https://www.wilderssecurity.com/threads/setting-up-tor-proxomitron-sockscap.55748/
#tor opens port tcp 9050 on localhost for applications to connect
#bitcoin 8333
#bitmessage 8444

#DESTINATION UDP PORTS
#dns 53 (dnscrypt 443)
#dhcp 67 (server) 68 (client) #ISC related software bypases these by using raw sockets
#ntp 123
#traceroute 33434:33523

#ICMP TYPE
#Echo Reply 0
#Destination Unreachable 3
#Echo 8
#Time Exceeded 11

#INFO ABOUT DESIGN
#nf_conntrack_ftp module must be loaded for FTP to work

#statefull filtering section filters packets by state into custom chains first
#each custom chain then filters according to port, protocol etc...

#log custom chains are used by other custom chains for logging according to
#kernel log levels


#each rule or set of rules have a comment: protocol/program, server/client (info)

