#!/bin/bash

echo "flush iptable rules"
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X

echo "Set to ACCEPT chain rules for which is ESTABLISHED,RELATED"
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "Allow ssh communication between firewall and your machine"
sudo iptables -A INPUT -s your_ip -d firewall_ip -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

echo "Allowing DNS lookups (tcp, udp port 53) to server"
sudo iptables -A OUTPUT -p tcp -m tcp --dport 53 -m state --state NEW -j ACCEPT
sudo iptables -A OUTPUT -p udp -m udp --dport 53 -m state --state NEW -j ACCEPT
sudo iptables -A INPUT  -p tcp -m tcp --sport 53 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT  -p udp -m udp --sport 53 -m state --state RELATED,ESTABLISHED -j ACCEPT

echo "Allow port 80"
sudo iptables -A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT  -p tcp -m tcp --sport 80 -j ACCEPT
sudo iptables -A OUTPUT -p udp -m udp --dport 80 -j ACCEPT
sudo iptables -A INPUT  -p udp -m udp --sport 80 -j ACCEPT

sudo echo "1" > /proc/sys/net/ipv4/ip_forward
sudo sysctl net.ipv4.ip_forward=1

echo "Allow port redirection to webServer's port 80"
sudo iptables -t nat -A PREROUTING -i ens18 -p tcp --dport 80 -j DNAT --to-destination web_server_ip
sudo iptables -A FORWARD -i ens18 -d web_server_ip -p tcp --dport 80 -j ACCEPT
#sudo iptables -A FORWARD -i ens18 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o ens18 -j MASQUERADE 

echo "Log before dropping"
sudo iptables -N LOGGING
sudo iptables -A INPUT -j LOGGING
sudo iptables -A FORWARD -j LOGGING
sudo iptables -A OUTPUT -j LOGGING
sudo iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped : " --log-level 4

echo "Set default policy to 'DROP'"
sudo iptables -P INPUT   DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT  DROP

exit 0