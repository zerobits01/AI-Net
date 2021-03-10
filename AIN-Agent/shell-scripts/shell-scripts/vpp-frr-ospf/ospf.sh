#!/bin/bash

######################################################
# puprose: installing vpp and other requirements
# date created: 2021/2/6
# desc: #
######################################################


sudo cp -f ./daemons /etc/frr/daemons
sudo cp -f ./ospfd.conf /etc/frr/

sudo systemctl restart frr.service
sudo systemctl restart vpp.service

# configuring interfaces and tunnel on vpp
sudo vppctl exec `pwd`/ospf.txt

# enabling tap in linux for routing the traffic to the other side
sudo ip link set vxlan-out up
sudo ip addr add 20.20.20.1/24 dev vxlan-out


