#!/usr/bin/python
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, IVSSwitch, UserSwitch
from mininet.link import Link, TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

import os
import sys
from time import sleep

def topology():
    net = Mininet( controller=Controller, link=TCLink, switch=OVSKernelSwitch )
    s1 = net.addSwitch( 's1')
    s2 = net.addSwitch( 's2')
    s3 = net.addSwitch( 's3')
    s4 = net.addSwitch( 's4')
    s5 = net.addSwitch( 's5')
    s6 = net.addSwitch( 's6')
    s7 = net.addSwitch( 's7')
    h1 = net.addHost( 'h1')
    h2 = net.addHost( 'h2')
    h3 = net.addHost( 'h3')
    h4 = net.addHost( 'h4')
    c0 = net.addController( 'c0' , controller=RemoteController, ip='127.0.0.1' , port=6653 )
    net.addLink(s1, s2, bw=16, delay='5ms', max_queue_size=1000,  use_htb=True)
    net.addLink(s1, s6, bw=16, delay='5ms', max_queue_size=1000,  use_htb=True)
    net.addLink(s2, s3, bw=16, delay='1ms', max_queue_size=1000,  use_htb=True)
    net.addLink(s3, s4, bw=16, delay='6ms', max_queue_size=1000,  use_htb=True)
    net.addLink(s3, s5, bw=16, delay='1ms', max_queue_size=1000,  use_htb=True)
    net.addLink(s4, s7, bw=8, delay='4ms', max_queue_size=1000,  use_htb=True)
    net.addLink(s5, s6, bw=8, delay='5ms', max_queue_size=1000,  use_htb=True)
    net.addLink(s6, s7, bw=8, delay='3ms', max_queue_size=1000,  use_htb=True)
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s4)
    net.addLink(h4, s4)
    net.build()
    net.start()
    c0.start()
    print "The Network Has been Started"
    s2.start( [c0] )
    s1.start( [c0] )
    s3.start( [c0] )
    s4.start( [c0] )
    s5.start( [c0] )
    s6.start( [c0] )
    s7.start( [c0] )
    CLI( net )
    net.stop()
if __name__ == '__main__':
    setLogLevel( 'info' )
    topology()



