#!/usr/sbin/nft -f

#NOTE: nf_conntrack_ftp module should be mentioned in /etc/modules to load at boot time to make passive FTP work
#NOTE: with kernel 4.7 you need "net.netfilter.nf_conntrack_helper = 1" in sysctl.conf to continue things like PASV FTP

#
# PREPARE NFTABLES
#

flush ruleset

#
# TABLE DECLARATIONS
#

add table ip client

#
# SETS DEFINITIONS
#

add set client tor_ports { type inet_service; }
#https://www.torproject.org/docs/faq.html.en#OutboundPorts
#9030 not used but mentioned
add element client tor_ports { 9001 }
#add element client tor_ports { 9030 }

#default tor ports not mentioned on official site
#https://www.wilderssecurity.com/threads/setting-up-tor-proxomitron-sockscap.55748/
#add element client tor_ports { 9001, 9002, 9003, 9004 }
#add element client tor_ports { 9030, 9031, 9032, 9033 }
#add element client tor_ports { 9100 }

#
# VARIABLES DEFINITIONS
#

#dnscrypt
define dnscrypt_port = 443
define dnscrypt_server = 185.60.147.77

#
# CHAIN DECLARATIONS
#

add chain ip client outbound {
	type filter hook output priority 0; policy drop;
}

add chain ip client inbound {
	type filter hook input priority 0; policy drop;
}

add chain ip client established_in
add chain ip client established_out
add chain ip client new_out
add chain ip client new_in
add chain ip client related_out
add chain ip client related_in

#
# LOOPBACK INTERFACE
#

add rule ip client inbound iif lo accept
add rule ip client outbound oif lo accept

#
# STATEFULL FILTERING
#

# established connection
add rule ip client outbound ct state established jump established_out
add rule ip client inbound ct state established jump established_in

# new connection
add rule ip client outbound ct state new jump new_out
add rule ip client inbound ct state new jump new_in

# related connection
add rule ip client outbound ct state related jump related_out
add rule ip client inbound ct state related jump related_in

# invalid connection
add rule ip client outbound ct state invalid log prefix "invalid " group 0 drop
add rule ip client inbound ct state invalid log prefix "invalid " group 0 drop

# untracked connection
add rule ip client outbound ct state untracked log prefix "untracked " group 0 drop
add rule ip client inbound ct state untracked log prefix "untracked " group 0 drop

# connection not processed by statefull rules
add rule ip client outbound log prefix "critical " group 0
add rule ip client inbound log prefix "critical " group 0

#
# INCLUSIONS
#

include "/home/baltazar/git/Firewall/outbound.sh"
include "/home/baltazar/git/Firewall/inbound.sh"


