#!/bin/bash

#####
# ipv6 ip6tables firewall
#####

#################################################################################
#
# 1. Configuration options
#
#
# 1.2 Local Area Network configuration.
#

LAN_IFACE="eth0"

LAN_IP6=`ip a ls $LAN_IFACE | grep inet6 | grep link | awk {'print $2'}`
LAN_IP6_GLOB=`ip a ls $LAN_IFACE | grep inet6 | grep global | awk {'print $2'}`

#
# 1.4 Localhost Configuration
#

LO_IFACE="lo"
LO_IP6="::1/128"

#
# 1.5 IPTables Configuration
#

IPT6=/sbin/ip6tables

#################################################################################
#
# 2. Module loading.
#

MP=/sbin/modprobe

#
# Needed to initially load modules
#

/sbin/depmod -a

#
# 2.1 Required modules
#

$MP ipv6
$MP ip6_tables
$MP ip6table_filter
$MP nf_conntrack_ipv6

#
# 2.3 Flush firewall
#

$IPT6 -t filter -F
$IPT6 -t mangle -F
$IPT6 -t raw -F

$IPT6 -t filter -X
$IPT6 -t mangle -X
$IPT6 -t raw -X

#################################################################################
#
# 3. Rules set up.
#

#########################################
#
# 3.1 Filter table
#

#####################
#
# 3.1.1 set policies
#

$IPT6 -t filter -P INPUT DROP
$IPT6 -t filter -P OUTPUT DROP
$IPT6 -t filter -P FORWARD DROP

printf "."

#####################
#
# 3.1.2 Create custom chains
#

# for box itself
# (input)
$IPT6 -t filter -N bad-ifi6 # public interface of router
$IPT6 -t filter -N good-ifi6 # lan interface of router
$IPT6 -t filter -N wlan-ifi6 # wifi interface of router
$IPT6 -t filter -N lo-ifi6 # loopback
# (output)
$IPT6 -t filter -N bad-ifo6
$IPT6 -t filter -N good-ifo6
$IPT6 -t filter -N wlan-ifo6
$IPT6 -t filter -N lo-ifo6

# forward (traffic traversal)
$IPT6 -t filter -N good-bad-6
$IPT6 -t filter -N wlan-bad-6
$IPT6 -t filter -N bad-good-6
$IPT6 -t filter -N bad-wlan-6
$IPT6 -t filter -N wlan-good-6
$IPT6 -t filter -N good-wlan-6

#####################
#
# bad iface (input)
#

# ipv6
# get back established
$IPT6 -t filter -A bad-ifi6 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT6 -t filter -A bad-ifi6 -p udp -m state --state ESTABLISHED -j ACCEPT
$IPT6 -t filter -A bad-ifi6 -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT

# allow icmp
$IPT6 -t filter -A bad-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 135/0 -j ACCEPT # neighbour solicitation
$IPT6 -t filter -A bad-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 136/0 -j ACCEPT # neighbour advertisement
$IPT6 -t filter -A bad-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 143/0 -j ACCEPT # v2 multicast listener report

# allow any ll traffic from defaul gw
#$IPT6 -t filter -A bad-ifi6 -p all -s fe80::xxxx:xxxx:xxxx:xxxx/64 -j ACCEPT

# multicast ping requests accepted from WAN iface
$IPT6 -t filter -A bad-ifi6 -d ff02::1 -p icmpv6 -m icmp6 --icmpv6-type 128/0 -j ACCEPT
$IPT6 -t filter -A bad-ifi6 -d ff02::2 -p icmpv6 -m icmp6 --icmpv6-type 128/0 -j ACCEPT
# allow to receive pongs (does it work via conntrack?)
$IPT6 -t filter -A bad-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 129/0 -j ACCEPT
# allow multicast listener query from gw
$IPT6 -t filter -A bad-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 130/0 -j ACCEPT

# public ftp
#$IPT6 -t filter -A bad-ifi6 -p tcp --dport 21 --syn -j ACCEPT

# allow SSH from any
$IPT6 -t filter -A bad-ifi6 -p tcp --dport 22 --syn -j ACCEPT

# log and reject all other
$IPT6 -t filter -A bad-ifi6 -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "BADIF6 (IN): "
$IPT6 -t filter -A bad-ifi6 -j DROP

printf "."


#####################
#
# bad iface (output)
#

# conntrack
$IPT6 -t filter -A bad-ifo6 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT6 -t filter -A bad-ifo6 -p udp -m state --state ESTABLISHED -j ACCEPT
$IPT6 -t filter -A bad-ifo6 -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT

# disallow ntp multicast w/o logging
$IPT6 -t filter -A bad-ifo6 -p udp -d ff05::101 --dport 123 -j DROP

# allow any outgoing packets from THIS host
$IPT6 -t filter -A bad-ifo6 -p tcp --syn -j ACCEPT
$IPT6 -t filter -A bad-ifo6 -p udp -m state --state NEW -j ACCEPT

# allow pings out
$IPT6 -t filter -A bad-ifo6 -p icmpv6 -m icmp6 --icmpv6-type 128/0 -m state --state NEW -j ACCEPT
#
# all other icmps (need to check it all!)
$IPT6 -t filter -A bad-ifo6 -p icmpv6 -m state --state NEW -j ACCEPT
#

# log and reject all other
$IPT6 -t filter -A bad-ifo6 -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "BADIF6 (OUT): "
$IPT6 -t filter -A bad-ifo6 -j DROP

printf "."

#####################
#
# good iface (input)
#

# get back established
$IPT6 -t filter -A good-ifi6 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT6 -t filter -A good-ifi6 -p udp -m state --state ESTABLISHED -j ACCEPT
$IPT6 -t filter -A good-ifi6 -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT

# allow SSH from any
$IPT6 -t filter -A good-ifi6 -p tcp --dport 22 --syn -j ACCEPT

# allow DHCP
$IPT6 -t filter -A good-ifi6 -p udp --dport 547 -m state --state NEW -j ACCEPT

# allow netbios
$IPT6 -t filter -A good-ifi6 -p tcp --dport 445 --syn -j ACCEPT
$IPT6 -t filter -A good-ifi6 -p tcp --dport 139 --syn -j ACCEPT
$IPT6 -t filter -A good-ifi6 -p udp --dport 137 -m state --state NEW -j ACCEPT
$IPT6 -t filter -A good-ifi6 -p udp --dport 138 -m state --state NEW -j ACCEPT
$IPT6 -t filter -A good-ifi6 -p tcp --dport 135 --syn -j ACCEPT

# allow icmp
$IPT6 -t filter -A good-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 1/4 -j ACCEPT # port unreachable
$IPT6 -t filter -A good-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 128/0 -j ACCEPT # ping (echo request)
$IPT6 -t filter -A good-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 129/0 -j ACCEPT # pong (echo reply)
$IPT6 -t filter -A good-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 132/0 -j ACCEPT # Multicast Listener done
$IPT6 -t filter -A good-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 133/0 -j ACCEPT # Router Solicitation
$IPT6 -t filter -A good-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 134/0 -j ACCEPT # Router Advertisement
$IPT6 -t filter -A good-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 135/0 -j ACCEPT # Neighbour Solicitation
$IPT6 -t filter -A good-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 136/0 -j ACCEPT # Neighbour Advertisement

# allow (m)DNS
$IPT6 -t filter -A good-ifi6 -p udp --dport 53 -j ACCEPT
$IPT6 -t filter -A good-ifi6 -p udp --dport 5353 -j ACCEPT

# log and reject all other
$IPT6 -t filter -A good-ifi6 -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "GOODIF6 (IN): "
$IPT6 -t filter -A good-ifi6 -j DROP

printf "."

#####################
#
# WLAN iface (input)
#
# get back established
$IPT6 -t filter -A wlan-ifi6 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT6 -t filter -A wlan-ifi6 -p udp -m state --state ESTABLISHED -j ACCEPT
$IPT6 -t filter -A wlan-ifi6 -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT

# icmp v6
$IPT6 -t filter -A wlan-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 133/0 -j ACCEPT # multicast RS (Router solicitation)
$IPT6 -t filter -A wlan-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 134/0 -j ACCEPT # multicast RA (Router advertisement)
$IPT6 -t filter -A wlan-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 135/0 -j ACCEPT # multicast Neighbor Solicitation
$IPT6 -t filter -A wlan-ifi6 -p icmpv6 -m icmp6 --icmpv6-type 136/0 -j ACCEPT # neigh advert

# mdns
$IPT6 -t filter -A wlan-ifi6 -p udp --sport 5353 --dport 5353 -m state --state NEW -j ACCEPT

# allow DHCP
$IPT6 -t filter -A wlan-ifi6 -p udp --dport 547 -m state --state NEW -j ACCEPT

# log and reject all other
$IPT6 -t filter -A wlan-ifi6 -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "WLANIF6 (IN): "
$IPT6 -t filter -A wlan-ifi6 -j DROP

printf "."

#####################
#
# GOOD iface (output)
#

# get back established
$IPT6 -t filter -A good-ifo6 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT6 -t filter -A good-ifo6 -p udp -m state --state ESTABLISHED -j ACCEPT
$IPT6 -t filter -A good-ifo6 -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT

# allow (m)DNS queries to LAN
$IPT6 -t filter -A good-ifo6 -p udp --dport 53 -j ACCEPT
$IPT6 -t filter -A good-ifo6 -p udp --dport 5353 -j ACCEPT

# allow SSH from here to lan
$IPT6 -t filter -A good-ifo6 -p tcp --dport 22 --syn -j ACCEPT
# icmp
$IPT6 -t filter -A good-ifo6 -p icmpv6 -m icmp6 --icmpv6-type 128/0 -j ACCEPT # ping
$IPT6 -t filter -A good-ifo6 -p icmpv6 -m icmp6 --icmpv6-type 129/0 -j ACCEPT # pong
$IPT6 -t filter -A good-ifo6 -p icmpv6 -m icmp6 --icmpv6-type 130/0 -j ACCEPT # multicast listener query
$IPT6 -t filter -A good-ifo6 -p icmpv6 -m icmp6 --icmpv6-type 134/0 -j ACCEPT # RA
$IPT6 -t filter -A good-ifo6 -p icmpv6 -m icmp6 --icmpv6-type 135/0 -j ACCEPT # neigh solic
$IPT6 -t filter -A good-ifo6 -p icmpv6 -m icmp6 --icmpv6-type 136/0 -j ACCEPT # neigh advert
$IPT6 -t filter -A good-ifo6 -p icmpv6 -m icmp6 --icmpv6-type 137/0 -j ACCEPT # redirect
$IPT6 -t filter -A good-ifo6 -p icmpv6 -m icmp6 --icmpv6-type 143/0 -j ACCEPT # v2 multicast report

# allow ntp multicast
$IPT6 -t filter -A good-ifo6 -p udp -d ff05::101 --dport 123 -j ACCEPT

# allow DHCPD6
$IPT6 -t filter -A good-ifo6 -p udp --sport 547 --dport 546 -j ACCEPT

# allow outgoing netbios connections from server (?)
$IPT6 -t filter -A good-ifo6 -p tcp --dport 445 --syn -j ACCEPT
$IPT6 -t filter -A good-ifo6 -p tcp --dport 139 --syn -j ACCEPT

# log and reject all other
$IPT6 -t filter -A good-ifo6 -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "GOODIF6 (OUT): "
$IPT6 -t filter -A good-ifo6 -j DROP

printf "."

#####################
#
# WLAN iface (output)
#

# get back established
$IPT6 -t filter -A wlan-ifo6 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT6 -t filter -A wlan-ifo6 -p udp -m state --state ESTABLISHED -j ACCEPT
$IPT6 -t filter -A wlan-ifo6 -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT

# allow out icmpv6
$IPT6 -t filter -A wlan-ifo6 -p icmpv6 -m icmp6 --icmpv6-type 134/0 -j ACCEPT # RA
$IPT6 -t filter -A wlan-ifo6 -p icmpv6 -m icmp6 --icmpv6-type 135/0 -j ACCEPT # neigh solic
$IPT6 -t filter -A wlan-ifo6 -p icmpv6 -m icmp6 --icmpv6-type 136/0 -j ACCEPT # neigh advert
$IPT6 -t filter -A wlan-ifo6 -p icmpv6 -m icmp6 --icmpv6-type 143/0 -j ACCEPT # Version 2 Multicast Listener Report

# allow mdns
$IPT6 -t filter -A wlan-ifo6 -p udp --sport 5353 --dport 5353 -m state --state NEW -j ACCEPT

# allow ntp multicast
$IPT6 -t filter -A wlan-ifo6 -p udp -d ff05::101 --dport 123 -j ACCEPT

# log and reject all other
$IPT6 -t filter -A wlan-ifo6 -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "WLANIF6 (OUT): "
$IPT6 -t filter -A wlan-ifo6 -j DROP

printf "."


#####################
#
# Loopback (IN)
#

# allow all local IP's on loopback
$IPT6 -t filter -A lo-ifi6 -d $LO_IP6 -j ACCEPT
$IPT6 -t filter -A lo-ifi6 -d $LAN_IP6 -j ACCEPT
$IPT6 -t filter -A lo-ifi6 -d $LAN_IP6_GLOB -j ACCEPT

# reject all other
$IPT6 -t filter -A lo-ifi6 -j LOG --log-prefix "LOOPBACK6 (IN): "
$IPT6 -t filter -A lo-ifi6 -j DROP

printf "."

#####################
#
# Loopback (OUT)
#

# ipv6
# allow all local IP's on loopback
$IPT6 -t filter -A lo-ifo6 -d $LO_IP6 -j ACCEPT
$IPT6 -t filter -A lo-ifo6 -d $LAN_IP6 -j ACCEPT
$IPT6 -t filter -A lo-ifo6 -d $LAN_IP6_GLOB -j ACCEPT

# reject all other
$IPT6 -t filter -A lo-ifo6 -j LOG --log-prefix "LOOPBACK6 (OUT): "
$IPT6 -t filter -A lo-ifo6 -j DROP

printf "."

###############################
# FORWARD custom tables
###############################

######################################
#
# bad-good-6 chain
#

# get back established sessions
$IPT6 -t filter -A bad-good-6 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT6 -t filter -A bad-good-6 -p udp -m state --state ESTABLISHED -j ACCEPT
$IPT6 -t filter -A bad-good-6 -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT

# allow any v6 icmp with limit
$IPT6 -t filter -A bad-good-6 -p icmpv6 -m limit --limit 600/min -j ACCEPT
$IPT6 -t filter -A bad-good-6 -p icmpv6 -j DROP

# allow proto 59 with limit of 40 bytes
$IPT6 -t filter -A bad-good-6 -p ipv6-nonxt -m length --length 40 -j ACCEPT

# log with limit and reject all other
$IPT6 -t filter -A bad-good-6 -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "BAD-GOOD-6: "
$IPT6 -t filter -A bad-good-6 -j REJECT

printf "."

######################################
#
# good-bad-6 chain
#

# get back established sessions
$IPT6 -t filter -A good-bad-6 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT6 -t filter -A good-bad-6 -p udp -m state --state ESTABLISHED -j ACCEPT
$IPT6 -t filter -A good-bad-6 -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT

# allow any v6 icmp with limit
$IPT6 -t filter -A good-bad-6 -p icmpv6 -m limit --limit 600/min -j ACCEPT
$IPT6 -t filter -A good-bad-6 -p icmpv6 -j DROP

# allow proto 59 with limit of 40 bytes
$IPT6 -t filter -A good-bad-6 -p ipv6-nonxt -m length --length 40 -j ACCEPT

# log with limit and reject all other
$IPT6 -t filter -A good-bad-6 -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "GOOD-BAD-6: "
$IPT6 -t filter -A good-bad-6 -j REJECT

printf "."

######################################
#
# good-wlan-6 chain
#

# get back established sessions
$IPT6 -t filter -A good-wlan-6 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT6 -t filter -A good-wlan-6 -p udp -m state --state ESTABLISHED -j ACCEPT
$IPT6 -t filter -A good-wlan-6 -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT

# allow any v6 icmp with limit
$IPT6 -t filter -A good-wlan-6 -p icmpv6 -m limit --limit 600/min -j ACCEPT
$IPT6 -t filter -A good-wlan-6 -p icmpv6 -j DROP

# allow proto 59 with limit of 40 bytes
$IPT6 -t filter -A good-wlan-6 -p ipv6-nonxt -m length --length 40 -j ACCEPT

# log with limit and reject all other
$IPT6 -t filter -A good-wlan-6 -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "GOOD-WLAN-6: "
$IPT6 -t filter -A good-wlan-6 -j REJECT

printf "."

######################################
#
# bad-wlan-6 chain
#

# get back established sessions
$IPT6 -t filter -A bad-wlan-6 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT6 -t filter -A bad-wlan-6 -p udp -m state --state ESTABLISHED -j ACCEPT
$IPT6 -t filter -A bad-wlan-6 -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT

# allow any v6 icmp with limit
$IPT6 -t filter -A bad-wlan-6 -p icmpv6 -m limit --limit 600/min -j ACCEPT
$IPT6 -t filter -A bad-wlan-6 -p icmpv6 -j DROP

# allow proto 59 with limit of 40 bytes
$IPT6 -t filter -A bad-wlan-6 -p ipv6-nonxt -m length --length 40 -j ACCEPT

# log with limit and reject all other
$IPT6 -t filter -A bad-wlan-6 -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "BAD-WLAN-6: "
$IPT6 -t filter -A bad-wlan-6 -j REJECT

printf "."

######################################
#
# wlan-bad-6 chain
#

# get back established sessions
$IPT6 -t filter -A wlan-bad-6 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT6 -t filter -A wlan-bad-6 -p udp -m state --state ESTABLISHED -j ACCEPT
$IPT6 -t filter -A wlan-bad-6 -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT

# allow any v6 icmp with limit
$IPT6 -t filter -A wlan-bad-6 -p icmpv6 -m limit --limit 600/min -j ACCEPT
$IPT6 -t filter -A wlan-bad-6 -p icmpv6 -j DROP

# allow proto 59 with limit of 40 bytes
$IPT6 -t filter -A wlan-bad-6 -p ipv6-nonxt -m length --length 40 -j ACCEPT

# log with limit and reject all other
$IPT6 -t filter -A wlan-bad-6 -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "WLAN-BAD-6: "
$IPT6 -t filter -A wlan-bad-6 -j REJECT

printf "."

######################################
#
# wlan-good-6 chain
#

# get back established sessions
$IPT6 -t filter -A wlan-good-6 -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT6 -t filter -A wlan-good-6 -p udp -m state --state ESTABLISHED -j ACCEPT
$IPT6 -t filter -A wlan-good-6 -p icmpv6 -m state --state ESTABLISHED,RELATED -j ACCEPT

# allow any v6 icmp with limit
$IPT6 -t filter -A wlan-good-6 -p icmpv6 -m limit --limit 600/min -j ACCEPT
$IPT6 -t filter -A wlan-good-6 -p icmpv6 -j DROP

# allow proto 59 with limit of 40 bytes
$IPT6 -t filter -A wlan-good-6 -p ipv6-nonxt -m length --length 40 -j ACCEPT

# log with limit and reject all other
$IPT6 -t filter -A wlan-good-6 -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "WLAN-GOOD-6: "
$IPT6 -t filter -A wlan-good-6 -j REJECT

printf "."

#####################
#
# 3.1.4 INPUT chain
#

# Jumps
$IPT6 -t filter -A INPUT -i $LO_IFACE -j lo-ifi6
$IPT6 -t filter -A INPUT -i $LAN_IFACE -j good-ifi6

$IPT6 -t filter -A INPUT -j LOG --log-prefix "INPUT6 Packet died: "

printf "."

#####################
#
# 3.1.5 FORWARD chain
#

$IPT6 -t filter -A FORWARD -m limit --limit 3/min --limit-burst 3 -j LOG --log-prefix "FORWARD6 Packet died: "

printf "."

#####################
#
# 3.1.6 OUTPUT chain
#

$IPT6 -t filter -A OUTPUT -o $LO_IFACE -j lo-ifo6
$IPT6 -t filter -A OUTPUT -o $LAN_IFACE -j good-ifo6

$IPT6 -t filter -A OUTPUT -j LOG --log-prefix "OUTPUT6 Packet died: "

echo "."
#/usr/sbin/ip6tables-save > /etc/sysconfig/ip6tables

exit