#!/bin/bash

# Define the IP addresses
ip_gateway_eth0="172.29.4.225"
ip_vhost1_eth0="172.29.4.226"
ip_vhost1_eth1="172.29.4.228"
ip_vhost1_eth2="172.29.4.232"
ip_vhost2_eth0="172.29.4.229"
ip_vhost2_eth1="172.29.4.230"
ip_vhost2_eth2="172.29.4.237"
ip_vhost3_eth0="172.29.4.233"
ip_vhost3_eth1="172.29.4.234"
ip_vhost3_eth2="172.29.4.238"
ip_server1_eth0="172.29.4.231"
ip_server2_eth0="172.29.4.235"

# Create an array of IP addresses
ips=($ip_gateway_eth0 $ip_vhost1_eth0 $ip_vhost1_eth1 $ip_vhost1_eth2 $ip_vhost2_eth0 $ip_vhost2_eth1 $ip_vhost2_eth2 $ip_vhost3_eth0 $ip_vhost3_eth1 $ip_vhost3_eth2 $ip_server1_eth0 $ip_server2_eth0)

# Ping each IP address
for ip in "${ips[@]}"; do
  echo "Pinging $ip..."
  ping -c 2 $ip
  echo "-----------------------------------"
done

wget http://172.29.4.231:16280
wget http://172.29.4.235:16280
# wget http://172.29.4.231:16280/64MB.bin
# wget http://172.29.4.235:16280/64MB.bin

# Additional pings using vnltopo107.sh script
echo "Pinging from server1 to 172.29.4.235..."
./vnltopo114.sh server1 ping 172.29.4.235 -c 4
echo "-----------------------------------"

echo "Pinging from server2 to 172.29.4.231..."
./vnltopo114.sh server2 ping 172.29.4.231 -c 4
echo "-----------------------------------"