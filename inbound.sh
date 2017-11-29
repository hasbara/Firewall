
#
# NEW INBOUND CONNECTIONS
#

#dhcp client (broadcast offer - test rule since ISC use raw packets)
#add rule client new_in udp sport 67 udp dport 68 ip daddr 255.255.255.255 accept

#dhcp server (used for virtual wifi)
#add rule client new_in udp sport 68 udp dport 67 accept

#dns server (used for virtual wifi)
#add rule client new_in ip saddr 172.16.1.1/24 accept

#bitcoin (node)
#add rule client new_in tcp dport 8333 accept

#bitmessage (node)
#add rule client new_in tcp dport 8444 accept

#multicast
add rule client new_in meta pkttype multicast accept

#broadcast
add rule client new_in meta pkttype broadcast accept

#log
add rule client new_in log prefix "drop-new_in " group 0 drop

#
# ESTABLISHED INBOUND CONNECTIONS
#

#dhcp client
#add rule client established_in udp sport 67 udp dport 68 accept

#dhcp server
#add rule client established_in udp sport 68 udp dport 67 accept

#dns client
#add rule client established_in udp sport 53 accept
#add rule client established_in tcp sport 53 accept

#dns server (used by virtual wifi)
#add rule client established_in ip saddr 12.16.1.1/24 udp dport 53 accept

#dnscrypt (fetch server sertificates and DNS)
add rule client established_in udp sport $dnscrypt_port ip saddr $dnscrypt_server accept

#http, https, oscp, crl
add rule client established_in tcp sport { http, https } accept

#rtmp/e (Flash Media server)
#add rule client established_in tcp sport 1935 accept

#ntp client/server (ntpq)
#add rule client established_in udp sport 123 udp dport 123 accept

#ntp client (systemd-timesyncd)
#https://wiki.archlinux.org/index.php/systemd-timesyncd
add rule client established_in udp sport 123 accept

#ftp client (active and passive)
add rule client established_in tcp sport 21 tcp dport >1023 accept

#ftp client (active)
#add rule client established_in tcp sport 20 tcp dport >1023 accept

#ftp client (passive)
add rule client established_in tcp sport >1023 tcp dport >1023 accept

#ftps client
#add rule client established_in tcp sport 990 tcp dport >1023

#ssh client/server (used for github and filezilla)
add rule client established_in tcp sport 22 accept

#pop3
#add rule client established_in tcp sport 110 accept

#pop3s
#add rule client established_in tcp sport 995 accept

#smtp (MTA)
#add rule client established_in tcp sport 25 accept

#smtps (MSA)
#add rule client established_in tcp sport 587 accept

#smtps (MTA/MSA)
#add rule client established_in tcp sport 465 accept

#imap
#add rule client established_in tcp sport 143 accept

#imaps
#add rule client established_in tcp sport 993 accept

#git client
add rule client established_in tcp sport 9418 accept

#bitcoin
#add rule client established_in tcp sport 8333 accept

#bitmessage
#add rule client established_in tcp sport 8444 accept

#chess (fics)
#add rule client established_in tcp sport 5000 accept

#tor
#add rule client established_in tcp sport @tor_ports accept

#reply to ping
add rule client established_in icmp type echo-reply accept
add rule client established_in icmp type destination-unreachable accept
add rule client established_in icmp type time-exceeded accept

#log
add rule client established_in log prefix "drop-est-in " group 0 drop

#
# RELATED INBOUND CONNECTIONS
#

#ftp client (active)
#add rule client related_in tcp sport 20 tcp dport >1023 accept
 
#traceroute reply
add rule client related_in icmp type echo-reply accept
add rule client related_in icmp type destination-unreachable accept
add rule client related_in icmp type time-exceeded accept

#multicast
add rule client related_in meta pkttype multicast accept

#broadcast
add rule client related_in meta pkttype broadcast accept

#log
add rule client related_in log prefix "drop-rel-in " group 0 drop


