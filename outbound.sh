
#
# NEW OUTBOUND CONNECTIONS
#

#dhcp client
#add rule client new_out udp sport 68 udp dport 67 accept

#dns client UDP/TCP (probably server uses too)
#add rule client new_out udp dport 53 accept
#add rule client new_out tcp dport 53

#dnscrypt (fetch server certificates and DNS)
add rule client new_out udp dport $dnscrypt_port ip daddr $dnscrypt_server accept

#http, https, oscp, crl (also used by tor)
add rule client new_out tcp dport { http, https } accept

#rtmp/e (Flash Media Server)
#add rule client new_out tcp dport 1935 accept

#ntp client/server (ntpd)
#add rule client new_out tcp sport 123 tcp dport 123 accept

#ntp client (systemd-timesyncd)
#https://wiki.archlinux.org/index.php/systemd-timesyncd
add rule client new_out udp dport 123 accept

#ftp client (active and pasive)
add rule client new_out tcp sport >=1024 tcp dport 21 accept

#ftps client
#add rule client new_out tcp sport >=1024 tcp dport 990 accept

#ssh/sftp client (used by git and filezilla)
add rule client new_out tcp dport 22 accept

#pop3
#add rule client new_out tcp dport 110 accept

#pop3s
#add rule client new_out tcp dport 995 accept

#smtp (MTA)
#add rule client new_out tcp dport 25 accept

#smtps (MSA)
#add rule client new_out tcp dport 587 accept

#smtps (MTA/MSA)
#add rule client new_out tcp dport 465 accept

#imap
#add rule client new_out tcp dport 143 accept

#imaps
#add rule client new_out tcp dport 993 accept

#git
add rule client new_out tcp dport 9418 accept

#chess (fics (timeseal needs to open port - see netstat) )
#add rule client new_out tcp dport 5000 accept

#tor
#add rule client new_out tcp dport @tor_ports accept

#bitcoin
#add rule client new_out tcp dport 8333 accept

#bitmessage
#add rule client new_out tcp dport 8444 accept

#ping
add rule client new_out icmp type echo-request accept

#traceroute
add rule client new_out udp dport 33434-33523 accept

#multicast/broadcast
add rule client new_out meta pkttype multicast
add rule client new_out meta pkttype broadcast

#log
add rule client new_out log prefix "drop-new-out " group 0 drop

#
# ESTABLISHED OUTBOUND CONNECTIONS
#

#dhcp client
#add rule client established_out udp sport 68 udp dport 67 accept

#dhcp server (used by virtual wifi)
#add rule client established_out udp sport 67 udp dport 68 accept

#dns client UDP/TCP (probably server uses too)
#add rule client established_out udp dport 53 accept
#add rule client established_out tcp dport 53 accept

#dns server (used by virtual wifi)
#add rule client established_out udp sport 53 ip daddr 172.16.1.1/24 accept

#dnscrypt
add rule client established_out udp dport $dnscrypt_port ip daddr $dnscrypt_server accept

#http, https, oscp, crl
add rule client established_out tcp dport { http, https } accept

#rtmp/e (Flash media server)
#add rule client established_out udp dport 1935 accept

#ntp client/server (ntpq)
#add rule client established_out udp sport 123 udp dport 123 accept

#ftp (active and passive)
add rule client established_out tcp sport >=1024 tcp dport 21 accept

#ftp (active)
#add rule client established_out tcp sport >=1024 tcp dport 20 accept

#ftp (passive)
add rule client established_out tcp sport >=1024 tcp dport >=1024 accept

#ftps
#add rule client established_out tcp sport 1024 tcp dport 990 accept

#ssh client/server (used for github and filezilla)
add rule client established_out tcp dport 22 accept

#pop3
#add rule client established_out tcp dport 110 accept 

#pop3s
#add rule client established_out tcp dport 995 accept 

#smtp (MTA)
#add rule client established_out tcp dport 25 accept 

#smtp (MSA)
#add rule client established_out tcp dport 587 accept 

#smtp (MTA/MSA)
#add rule client established_out tcp dport 465 accept 

#imap
#add rule client established_out tcp dport 143 accept 

#imaps
#add rule client established_out tcp dport 993 accept

#git client
add rule client established_out tcp dport 9418 accept

#bitcoin client
#add rule client established_out tcp dport 8333 accept

#bitmessage
#add rule client established_out tcp dport 8444 accept

#chess (fics)
#add rule client established_out tcp dport 5000 accept

#tor
#add rule client established_out tcp dport @tor_ports accept

#ping
add rule client established_out icmp type echo-request accept

#log
add rule client established_out log prefix "drop-est-out " group 0 drop

#
# RELATED OUTBOUND CONNECTIONS
#

#ftp client (passive)
add rule client related_out tcp sport >=1024 tcp dport >=1024 accept

#reply to dns
add rule client related_out icmp type echo-reply accept

#multicast
add rule client related_out meta pkttype multicast accept

#broadcast
add rule client related_out meta pkttype broadcast accept

#log
add rule client related_out log prefix "drop-rel-out " group 0 drop

