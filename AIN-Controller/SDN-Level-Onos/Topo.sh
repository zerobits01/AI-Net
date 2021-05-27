#!/usr/bin/python
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, UserSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import Link, TCLink


def topology():
  net = Mininet(controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)
  c1 = net.addController( 'c1', controller=RemoteController, ip='172.17.0.5', port=6653 )
  c2 = net.addController( 'c2', controller=RemoteController, ip='172.17.0.6', port=6653 )
  c3 = net.addController( 'c3', controller=RemoteController, ip='172.17.0.7', port=6653 )
  s1 = net.addSwitch('s1')
  s2 = net.addSwitch('s2')
  s3 = net.addSwitch('s3')
  s4 = net.addSwitch('s4')
  s5 = net.addSwitch('s5')
  s6 = net.addSwitch('s6')
  
  h1 = net.addHost('h1')
  h2 = net.addHost('h2')
  h3 = net.addHost('h3')
  h4 = net.addHost('h4')
 
  net.addLink(s1 ,h3)
  net.addLink(s1 ,h4)
  net.addLink(s5 ,s1)
  net.addLink(s3 ,s6)
  net.addLink(s3 ,s2)
  net.addLink(s3 ,s4)
  net.addLink(s6 ,h1)
  net.addLink(s6 ,h2)


  net.addLink(s1 , s2 ,delay='15ms' ,bw=6 ,loss=3)
  net.addLink(s5 , s4 ,delay='13ms' ,bw=8 ,loss=9)
  net.addLink(s2 , s5 ,delay='12ms' ,bw=2 ,loss=4)
  net.addLink(s4 , s6 ,delay='15ms' ,bw=2 ,loss=23)

  
  net.build()
  net.start()
  c1.start()
  c2.start()
  c3.start()
  s1.start([c1])
  s2.start([c2])
  s3.start([c3])
  s4.start([c1])
  s5.start([c2])
  s6.start([c3])

  CLI( net )
  net.stop()


if __name__ == '__main__':
  setLogLevel( 'info' )
  topology()