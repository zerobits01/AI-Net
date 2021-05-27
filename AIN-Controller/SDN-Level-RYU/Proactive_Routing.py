#run as follows
#sudo mn --topo linear,3 --mac --controller=remote,ip=127.0.0.1,port=6653 --switch ovsk
#ryu run --observe-links  ryu/app/gui_topology/gui_topology.py ryu/app/Proactive_Routing.py


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
#Proactive_Routing
from ryu.lib.packet import ipv4
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.topology.api import get_host
from ryu.lib import hub
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
import copy
import datetime
import time
from ryu.lib.packet import arp
from ryu.lib import dpid as dpid_lib
from threading import Timer
from collections import defaultdict

class Proactive_Routing(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Proactive_Routing, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        #Proactive_Routing
        self.hosts_spec = []
        self.datapaths = {}
        self.hosts = {}
        self.Graph_topo=[]
        self.PortMap_topo=[]
        self.topo_raw_switches = []
        self.topo_raw_links = []        
        self.IDLE_TIMEOUT = 3600 #hosts expiration timer
        Timer(self.IDLE_TIMEOUT, self.expireHostEntries).start()
        #Timer(self.IDLE_TIMEOUT, self.inform_and_install).start()
        self.monitor_thread = hub.spawn(self.install_paths)	

    def expireHostEntries(self):
        expiredEntries = []
        for key,val in self.hosts.items():
            if int(time.time()) > val['timestamp'] + self.IDLE_TIMEOUT:
                expiredEntries.append(key)

        for ip in expiredEntries:
            del self.hosts[ip]

        Timer(self.IDLE_TIMEOUT, self.expireHostEntries).start()

    def updateHostTable(self, srcIP, dpid, port):
        self.hosts[srcIP]['timestamp'] = int(time.time())
        self.hosts[srcIP]['dpid'] = dpid
        self.hosts[srcIP]['port'] = port  
    def  show_host_table(self):
        for keys,values in self.hosts.items():
            print(keys)
            print(values)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)        

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def install_paths(self):
        while True:
            self.inform_and_install()
            hub.sleep(10) #in seconds
    def inform_and_install(self):
        hosts = get_host(self, None)
        for host in hosts:
            self.logger.info("host=%s",host)

        switches = get_switch(self, None)
        for s in switches:
            self.logger.info("switch=%s",s)                    

        print("number of switches=",len(switches))
        links = get_link(self, None)
        print("number of links=",len(links))                
        for link in links:
            self.Graph_topo[int(link.src.dpid)-1][int(link.dst.dpid)-1]=1 
        self.linkslist = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links]                    
        self.logger.info("Links %s", self.linkslist) 
        links_list = get_link(self, None)
        mylinks=[(link.src.dpid,link.dst.dpid,link.src.port_no,link.dst.port_no) for link in links_list]
        for s1,s2,port1,port2 in mylinks:
            self.PortMap_topo[int(s1)-1][int(s2)-1]=port1
            self.PortMap_topo[int(s2)-1][int(s1)-1]=port2 
        self.show_host_table()  
        self.topo_raw_switches=switches                  
        if len(switches)!=0 and len(links)!=0 :
            for x in range(len(switches)):
                for y in range(len(switches)):
                    print(self.Graph_topo[x][y]," ",end=" ")
                print()
            for x in range(len(switches)):
                for y in range(len(switches)):
                    print(self.PortMap_topo[x][y]," ",end=" ")
                print() 
            for keys1,values1 in self.hosts.items():
                for keys2,values2 in self.hosts.items():
                    if keys1!=keys2:
                        print(values1["mac"]," ",values2["mac"]," ",values1["port"]," ",values2["port"],keys1," ",keys2)
                        p=self.get_path(int(values1["dpid"]),int(values2["dpid"]),values1["port"],values2["port"])
                        if p!=None:
                            self.install_path_withIP(p,keys1,keys2)
                            #self.install_path_withmac(p,values1["mac"],values2["mac"])
                            #reverse path calculation
                        print(values2["mac"]," ",values1["mac"]," ",values2["port"]," ",values1["port"],keys2," ",keys1)
                        p=self.get_path(int(values2["dpid"]),int(values1["dpid"]),values2["port"],values1["port"])
                        if p!=None:
                            self.install_path_withIP(p,keys2,keys1)
                            #self.install_path_withmac(p,values1["mac"],values2["mac"])                                                            

                #hub.sleep(10)                  

    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return

        #find mac
        x=0
        pkt = packet.Packet()
        for keys1,values1 in self.hosts.items():
            if str(keys1)==str(pkt_arp.dst_ip):
                x=values1["mac"]
        if x!=0:
            pkt = packet.Packet()
            pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                            dst=pkt_ethernet.src,
                                           src=x))
            pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                  src_mac=x,
                                 src_ip=pkt_arp.dst_ip,
                                 dst_mac=pkt_arp.src_mac,
                                 dst_ip=pkt_arp.src_ip))

        self._send_packet(datapath, port, pkt)
    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        arp_pkt = pkt.get_protocol(arp.arp)        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]


        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        srcIP=""
        srcMac = eth.src
        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocols(ipv4.ipv4)[0]
            srcIP = ip.src  
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            srcIP = pkt_arp.src_ip
        #print(srcIP)             
        if srcIP not in self.hosts and srcIP!="":
            self.hosts[srcIP] = {}   
            # Always update MAC and switch-port location, just in case
            # DHCP reassigned the IP or the host moved
            self.hosts[srcIP]['mac'] = srcMac
            self.updateHostTable(srcIP, dpid_lib.dpid_to_str(datapath.id), in_port)

        if pkt_arp:
            self._handle_arp(datapath, in_port, eth, pkt_arp)
            return          



    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        # The Function get_switch(self, None) outputs the list of switches.
        self.topo_raw_switches = copy.copy(get_switch(self, None))
        # The Function get_link(self, None) outputs the list of links.
        self.topo_raw_links = copy.copy(get_link(self, None))
        self.Graph_topo = [[0 for x in range(len(self.topo_raw_switches))] for y in range(len(self.topo_raw_switches))] 
        self.PortMap_topo = [[0 for x in range(len(self.topo_raw_switches))] for y in range(len(self.topo_raw_switches))] 
        print("number of links=",len(self.topo_raw_links))                
        try:
            links_list = get_link(self, None)
            mylinks=[(link.src.dpid,link.dst.dpid,link.src.port_no,link.dst.port_no) for link in links_list]
            if len(self.topo_raw_switches) > 0:
                for s1,s2,port1,port2 in mylinks:
                    self.PortMap_topo[int(s1)-1][int(s2)-1]=port1
                    self.PortMap_topo[int(s2)-1][int(s1)-1]=port2
                    self.Graph_topo[int(s1)-1][int(s2)-1]=1 
                    self.Graph_topo[int(s2)-1][int(s1)-1]=1 
        except:
            print("an exception was occured")
        """
        Now you have saved the links and switches of the topo. So you could do all sort of stuf with them. 
        """

        print(" \t" + "Current Links:")
        for l in self.topo_raw_links:
            print (" \t\t" + str(l))

        print(" \t" + "Current Switches:")
        for s in self.topo_raw_switches:
            print (" \t\t" + str(s))

    """
    This event is fired when a switch leaves the topo. i.e. fails.
    """
    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        self.logger.info("Not tracking Switches, switch leaved.")                    

    def get_path (self,src,dst,first_port,final_port):

        #Dijkstra's algorithm

        print ("get_path is called, src=",src," dst=",dst, " first_port=", first_port, " final_port=", final_port)

        distance = {}

        previous = {}

        sws = get_switch(self, None)
        switches=[switch.dp.id for switch in sws]

        for dpid in switches:

            distance[dpid] = float('Inf')

            previous[dpid] = None



        distance[src]=0


        Q=set(switches)
        print(distance)

        while len(Q)>0:

            u = self.minimum_distance(distance, Q)
            if u==0 :
                return
            Q.remove(u)



            for p in switches:

                if self.Graph_topo[int(u)-1][int(p)-1]!=0:

                    w = 1

                    if distance[u] + w < distance[p]:

                        distance[p] = distance[u] + w

                        previous[p] = u



        r=[]

        p=dst

        r.append(p)

        q=previous[p]

        while q is not None:

            if q == src:

                r.append(q)

                break

            p=q

            r.append(p)

            q=previous[p]



        r.reverse()

        if src==dst:

            path=[src]

        else:

            path=r



        # Now add the ports

        r = []

        in_port = first_port

        for s1,s2 in zip(path[:-1],path[1:]):

            out_port = self.PortMap_topo[int(s1)-1][int(s2)-1]

            r.append((s1,in_port,out_port))

            in_port = self.PortMap_topo[int(s2)-1][int(s1)-1]

        r.append((dst,in_port,final_port))
        print ("path is=",r)
        return r        

    def minimum_distance(self,distance, Q):

        min = float('Inf')

        node = 0

        for v in Q:
            if distance[v] < min:
                min = distance[v]
                node = v

        return node  


    def install_path_withmac(self, p, src_mac, dst_mac):

        print ("install_path is called")
        sws = get_switch(self, None)
        switches=[switch.dp for switch in sws]
        datapath = switches[0] #initialization (not important:we should find relevant datapath)
        for sw, in_port, out_port in p:
            for s in switches:#find relevant datapath
                if int(s.id)==int(sw):
                    datapath=s

            ofproto = datapath.ofproto

            parser = datapath.ofproto_parser 

            print (src_ip,"->", dst_ip, "via ", sw, " in_port=", in_port, " out_port=", out_port)


            match=parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)#,ipv4_src="10.0.0.3")

            actions=[parser.OFPActionOutput(out_port)]

            #datapath=switches[int(sw)-1]


            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS , actions)]

            mod = datapath.ofproto_parser.OFPFlowMod(

                     datapath=datapath, match=match, idle_timeout=0, hard_timeout=0,

                 priority=1, instructions=inst)

            datapath.send_msg(mod) 

    def install_path_withIP(self, p, src_ip, dst_ip):



        print ("install_path_withIP is called ",src_ip," ",dst_ip, " " )
        sws = get_switch(self, None)
        switches=[switch.dp for switch in sws]
        datapath = switches[0] #initialization (not important:we should find relevant datapath)
        for sw, in_port, out_port in p:
            for s in switches:#find relevant datapath
                if int(s.id)==int(sw):
                    datapath=s

            ofproto = datapath.ofproto

            parser = datapath.ofproto_parser 

            print (src_ip,"->", dst_ip, "via ", sw, " in_port=", in_port, " out_port=", out_port)


            match=parser.OFPMatch(in_port=in_port,  eth_type=0x0800, ipv4_src=str(src_ip), ipv4_dst=str(dst_ip))

            actions=[parser.OFPActionOutput(out_port)]                 

            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS , actions)]

            mod = datapath.ofproto_parser.OFPFlowMod(

                     datapath=datapath, match=match, idle_timeout=0, hard_timeout=0,

                 priority=500, instructions=inst)

            datapath.send_msg(mod)                  



