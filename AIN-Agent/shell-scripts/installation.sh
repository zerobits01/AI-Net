#!/bin/bash

######################################################
# puprose: installing vpp and other requirements
# date created: 2021/2/6
# desc: #
######################################################


echo "############################"
echo "starting vpp installation"
echo "############################"
echo 

echo "############################"
echo "updating repos"
echo "############################"
echo 

apt-get update


echo "############################"
echo "installing curl"
echo "############################"
echo 

apt-get install curl


echo "############################"
echo "adding fdio repo"
echo "############################"
echo 

echo "deb [trusted=yes] https://packagecloud.io/fdio/release/ubuntu bionic main"\
     > /etc/apt/sources.list.d/99fd.io.list

curl -L https://packagecloud.io/fdio/release/gpgkey | sudo apt-key add -

apt-get update

echo "############################"
echo "downloading and installing requirments"
echo "############################"
echo 

wget http://archive.ubuntu.com/ubuntu/pool/universe/m/mbedtls/libmbedcrypto1_2.8.0-1_amd64.deb
wget http://archive.ubuntu.com/ubuntu/pool/universe/m/mbedtls/libmbedtls10_2.8.0-1_amd64.deb

apt-get install ./*.deb

echo "############################"
echo "installing main packages"
echo "############################"
echo 

apt-get install vpp vpp-plugin-core vpp-plugin-dpdk


echo "############################"
echo "installing recommended and apis"
echo "############################"
echo 

apt-get install vpp-api-python python3-vpp-api vpp-dbg vpp-dev



echo "############################"
echo "installing igb_uio module for pci connections"
echo "############################"
echo 

apt-get install dpdk-igb-uio-dkms


# loading the kernel module
modprobe igb_uio