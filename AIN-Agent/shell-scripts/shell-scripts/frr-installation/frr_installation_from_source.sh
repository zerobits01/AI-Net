#!/bin/bash
###########################################################################################
# author: zerobits01
# date:   2/16/2021
# puspose:FRR installation from source
###########################################################################################

uname -a 
# Linux vppedge1 5.8.0-43-generic #49~20.04.1-Ubuntu SMP Fri Feb 5 09:57:56 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux


###########################################################################################
# installing dependencies
sudo apt update
sudo apt-get install \
   git autoconf automake libtool make libreadline-dev texinfo \
   pkg-config libpam0g-dev libjson-c-dev bison flex python3-pytest \
   libc-ares-dev python3-dev libsystemd-dev python-ipaddress python3-sphinx \
   install-info build-essential libsystemd-dev libsnmp-dev perl \
   libcap-dev 

# python2 curl vim openconnect

###########################################################################################
   
# creating python3 sim link

sudo rm -f $(which python)

sudo ln -s /usr/bin/python3 /usr/bin/python



###########################################################################################

# adding pip2 version to ubuntu

curl https://bootstrap.pypa.io/get-pip.py --output get-pip.py
sudo pip3 install testresources
sudo python ./get-pip.py

# And verify the installation
# pip2 --version

###########################################################################################

# installing yang for netconf


sudo apt install cmake libpcre3-dev

git clone https://github.com/CESNET/libyang.git
cd libyang
mkdir build; cd build
cmake -DENABLE_LYD_PRIV=ON -DCMAKE_INSTALL_PREFIX:PATH=/usr \
      -D CMAKE_BUILD_TYPE:String="Release" ..
make
sudo make install

sudo apt-get install protobuf-c-compiler libprotobuf-c-dev

sudo apt-get install libzmq5 libzmq3-dev

###########################################################################################

# adding user and groups
sudo groupadd -r -g 92 frr
sudo groupadd -r -g 85 frrvty
sudo adduser --system --ingroup frr --home /var/run/frr/ \
   --gecos "FRR suite" --shell /sbin/nologin frr
sudo usermod -a -G frrvty frr

# compile

git clone https://github.com/frrouting/frr.git frr
cd frr


# git tag -l

git checkout frr-7.5

./bootstrap.sh
./configure \
    --prefix=/usr \
    --includedir=\${prefix}/include \
    --enable-exampledir=\${prefix}/share/doc/frr/examples \
    --bindir=\${prefix}/bin \
    --sbindir=\${prefix}/lib/frr \
    --libdir=\${prefix}/lib/frr \
    --libexecdir=\${prefix}/lib/frr \
    --localstatedir=/var/run/frr \
    --sysconfdir=/etc/frr \
    --with-moduledir=\${prefix}/lib/frr/modules \
    --with-libyang-pluginsdir=\${prefix}/lib/frr/libyang_plugins \
    --enable-configfile-mask=0640 \
    --enable-logfile-mask=0640 \
    --enable-snmp=agentx \
    --enable-multipath=64 \
    --enable-user=frr \
    --enable-group=frr \
    --enable-systemd=yes\
    --enable-vty-group=frrvty \
    --with-pkg-git-version \
    --with-pkg-extra-version=-MyOwnFRRVersion
make
sudo make install


# installation

sudo install -m 775 -o frr -g frr -d /var/log/frr
sudo install -m 775 -o frr -g frrvty -d /etc/frr
sudo install -m 640 -o frr -g frrvty tools/etc/frr/vtysh.conf /etc/frr/vtysh.conf
sudo install -m 640 -o frr -g frr tools/etc/frr/frr.conf /etc/frr/frr.conf
sudo install -m 640 -o frr -g frr tools/etc/frr/daemons.conf /etc/frr/daemons.conf
sudo install -m 640 -o frr -g frr tools/etc/frr/daemons /etc/frr/daemons


# enable ipforward
# net.ipv4.ip_forward=1
# net.ipv6.conf.all.forwarding=1


sudo echo mpls_router\\nmpls_iptunnel >> /etc/modules-load.d/modules.conf

sudo modprobe mpls-router mpls-iptunnel

# /etc/sysctl.conf
# Enable MPLS Label processing on all interfaces
# net.mpls.conf.enp3s0.input=1
# net.mpls.platform_labels=100000

sudo install -m 644 tools/frr.service /etc/systemd/system/frr.service
sudo systemctl enable frr

# /etc/frr/daemons
# watchfrr_enable=... and zebra=... etc. Enable the daemons as required by changing the value to yes.

sudo systemctl start frr

