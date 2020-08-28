#!/bin/bash

# Firewall IP
FW_IP="$(ip addr show ens18 | grep 'inet ' | cut -f2 | awk '{ print $2}')"

# Your DNS servers you use: cat /etc/resolv.conf
DNS_SERVER="8.8.4.4 8.8.8.8"

# Allow connections to this package servers
PACKAGE_SERVER="depo.pardus.org.tr"

echo "flush iptable rules"
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X

echo "Set default policy to 'DROP'"
sudo iptables -P INPUT   DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT  DROP

echo "Set to ACCEPT chain rules which is ESTABLISHED,RELATED"
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT


echo "Allow ssh communication between firewall and your machine"
sudo iptables -A INPUT -s source_ip -d destination_ip -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

for ip in $DNS_SERVER
do
	echo "Allowing DNS lookups (tcp, udp port 53) to server '$ip'"
	sudo iptables -A OUTPUT -p udp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	sudo iptables -A INPUT  -p udp -s $ip --sport 53 -m state --state RELATED,ESTABLISHED -j ACCEPT
	sudo iptables -A OUTPUT -p tcp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	sudo iptables -A INPUT  -p tcp -s $ip --sport 53 -m state --state RELATED,ESTABLISHED -j ACCEPT
done

echo "allow everything on localhost"
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

for ip in $PACKAGE_SERVER
do
	echo "Allow connection to '$ip' on port 21"
	sudo iptables -A OUTPUT -p tcp -d "$ip" --dport 21  -m state --state NEW,ESTABLISHED -j ACCEPT
	sudo iptables -A INPUT  -p tcp -s "$ip" --sport 21  -m state --state ESTABLISHED -j ACCEPT

	echo "Allow connection to '$ip' on port 80"
	sudo iptables -A OUTPUT -p tcp -d "$ip" --dport 80  -m state --state NEW,ESTABLISHED -j ACCEPT
	sudo iptables -A INPUT  -p tcp -s "$ip" --sport 80  -m state --state ESTABLISHED -j ACCEPT

	echo "Allow connection to '$ip' on port 443"
	sudo iptables -A OUTPUT -p tcp -d "$ip" --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
	sudo iptables -A INPUT  -p tcp -s "$ip" --sport 443 -m state --state ESTABLISHED -j ACCEPT
done

echo "Allowing new and established incoming connections to port 21, 80, 443"
sudo iptables -A INPUT  -p tcp -m multiport --dports 21,80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp -m multiport --sports 21,80,443 -m state --state ESTABLISHED -j ACCEPT

echo "Allow all outgoing connections to port 22"
sudo iptables -A OUTPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT  -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

echo "Allow outgoing icmp connections (pings,...)"
sudo iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT  -p icmp -m state --state ESTABLISHED,RELATED     -j ACCEPT

# Log before dropping
sudo iptables -N LOGGING
sudo iptables -A INPUT -j LOGGING
sudo iptables -A FORWARD -j LOGGING
sudo iptables -A OUTPUT -j LOGGING
sudo iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped : " --log-level 4

echo "Allow port redirection to webServer's port 80"
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination webServer_ip:80
sudo iptables -A FORWARD -d 172.16.103.185 -p tcp --dport 80 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -j MASQUERADE 

exit 0
