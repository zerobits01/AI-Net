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
from operator import attrgetter
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib import mac, hub
from ryu.topology import event, switches
import copy
from ryu.topology.api import get_switch, get_link
import time
from ryu.lib.packet import ethernet, ipv4, arp, ipv6, icmp
from ryu.lib.packet import ether_types, in_proto


class QoS_Routing(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(QoS_Routing, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topo_raw_switches = []
        self.topo_raw_links = [] 
        self.hosts_spec = []
        self.hosts_spec = []
        self.datapaths = {}
        self.hosts = {}        
        self.datapaths = {}        
        self.Graph_delay=[]
        self.Graph_Cost=[]
        self.Graph_plr=[]
        self.Graph_bw=[]
        self.PortMap_topo=[] 
        self.Graph_topo=[]
        self.PortMap_send=[]    
        self.PortMap_recv=[]    
        self.controller_mac = 'dd:dd:dd:dd:dd:dd' # decoy MAC
        self.controller_ip = '1.1.1.1' # decoy IP
        self.path_calculation_interval=20 #seconds
        self.Statistics_Gathering_Interval=17 #seconds
        self.Statistics_Gathering_Gap=self.path_calculation_interval - self.Statistics_Gathering_Interval-1
        self.IDLE_TIMEOUT = 3600 #hosts expiration timer
        Timer(self.IDLE_TIMEOUT, self.expireHostEntries).start()
        self.monitor_thread = hub.spawn(self.gather_statistcis)	        
        self.monitor_thread = hub.spawn(self.install_paths)
        
    def install_paths(self):
        while True:
            print("Calling Path Installer")
            hub.sleep(self.path_calculation_interval) #in seconds
            self.Link_Cost_Calc()
            self.inform_and_install()
            
    def gather_statistcis(self):
        while True:
            print("Calling Stattistics Gather")
            hub.sleep(self.Statistics_Gathering_Interval) #in seconds            
            self.monitor_link_bw()
            self.monitor_link_loss()
            self.monitor_link_delay() 
            hub.sleep(self.Statistics_Gathering_Gap)#to make assure all stats have been received
            self.calc_plr()
            self.show_PLR()   
            self.show_delay()
            self.show_bw()        
            
            
        
    def show_bw(self):
        try:
            print("*************BW Matrix*********************")                        
            switches = get_switch(self, None)
            links = get_link(self, None)            
            if len(switches)!=0 and len(links)!=0 :
                for x in range(len(switches)):
                    for y in range(len(switches)):
                        print(self.Graph_bw[x][y]," ",end=" ")
                    print() 
        except:
            pass    
        
    def show_delay(self):
        try:
            print("*************Delay Matrix*********************")                        
            switches = get_switch(self, None)
            links = get_link(self, None)            
            if len(switches)!=0 and len(links)!=0 :
                for x in range(len(switches)):
                    for y in range(len(switches)):
                        print(self.Graph_delay[x][y]," ",end=" ")
                    print() 
        except:
            pass
    def show_PLR(self):

        try:
            print("*************Packet Loss Matrix(loss)*********************")                        	    
            switches = get_switch(self, None)
            links = get_link(self, None)            
            if len(switches)!=0 and len(links)!=0 :
                for x in range(len(switches)):
                    for y in range(len(switches)):
                        print(self.Graph_plr[x][y]," ",end=" ")
                    print() 
            """print("*************Packet Loss Matrix(send)*********************")                        
            switches = get_switch(self, None)
            links = get_link(self, None)            
            if len(switches)!=0 and len(links)!=0 :
                for x in range(len(switches)):
                    for y in range(len(switches)):
                        print(self.PortMap_send[x][y]," ",end=" ")
                    print()    
            print("*************Packet Loss Matrix(rec)*********************")                        
            switches = get_switch(self, None)
            links = get_link(self, None)            
            if len(switches)!=0 and len(links)!=0 :
                for x in range(len(switches)):
                    for y in range(len(switches)):
                        print(self.PortMap_recv[x][y]," ",end=" ")
                    print() """              
        except:
            pass		                  

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev): 
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)        
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return   

        dst = eth.dst
        src = eth.src
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        srcIP=""
        srcMac = eth.src
        if eth.ethertype == ether_types.ETH_TYPE_IP and eth.dst!=self.controller_mac:
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
        
        
        #belo lines are used for handling delay packets
        if eth.ethertype == ether_types.ETH_TYPE_IP and eth.dst==self.controller_mac:        
            icmp_packet = pkt.get_protocol(icmp.icmp)
            echo_payload = icmp_packet.data
            #print("data=",echo_payload.data)
            payload = str(echo_payload.data.decode())
            info = payload.split(';')
            switch = info[0]
            latency = (time.time() - float(info[1])) * 1000 # in ms
            #print("delay from %d to %d is=%f",switch,datapath.id,latency)
            #print(latency)
            self.Graph_delay[int(switch)-1][int(datapath.id)-1]=latency
    def updateHostTable(self, srcIP, dpid, port):
        self.hosts[srcIP]['timestamp'] = int(time.time())
        self.hosts[srcIP]['dpid'] = dpid
        self.hosts[srcIP]['port'] = port  
    def  show_host_table(self):
        for keys,values in self.hosts.items():
            print(keys)
            print(values)
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
        
    def _request_desc_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser    
        # Request port/link descriptions, useful for obtaining bandwidth
        req = parser.OFPPortDescStatsRequest(datapath)
        datapath.send_msg(req)        
            
    def monitor_link_bw(self):
            try:
                links_list = get_link(self, None)
                mylinks=[(link.src.dpid,link.dst.dpid,link.src.port_no,link.dst.port_no) for link in links_list]
                self.topo_raw_switches=get_switch(self, None)
                if len(self.topo_raw_switches) > 0:
                    self.Graph_bw= [[0 for x in range(len(self.topo_raw_switches))] for y in range(len(self.topo_raw_switches))]                    
                    for s1,s2,port1,port2 in mylinks:
                        self.Graph_bw[int(s1)-1][int(s2)-1]=0
                        self.Graph_bw[int(s2)-1][int(s1)-1]=0                         
                for dp in self.datapaths.values():
                    self._request_desc_stats(dp)                
            except Exception as inst:     
                print("Exception=",inst)

            
    def monitor_link_loss(self):
            try:
                links_list = get_link(self, None)
                mylinks=[(link.src.dpid,link.dst.dpid,link.src.port_no,link.dst.port_no) for link in links_list]
                self.topo_raw_switches=get_switch(self, None)
                if len(self.topo_raw_switches) > 0:
                    self.PortMap_topo= [[0 for x in range(len(self.topo_raw_switches))] for y in range(len(self.topo_raw_switches))]                    
                    self.PortMap_send= [[0 for x in range(len(self.topo_raw_switches))] for y in range(len(self.topo_raw_switches))]                    
                    self.PortMap_recv= [[0 for x in range(len(self.topo_raw_switches))] for y in range(len(self.topo_raw_switches))]                    
                    self.Graph_plr= [[0 for x in range(len(self.topo_raw_switches))] for y in range(len(self.topo_raw_switches))]                    
                    for s1,s2,port1,port2 in mylinks:
                        self.PortMap_topo[int(s1)-1][int(s2)-1]=port1
                        self.PortMap_topo[int(s2)-1][int(s1)-1]=port2
                        self.PortMap_send[int(s1)-1][int(s2)-1]=0
                        self.PortMap_send[int(s2)-1][int(s1)-1]=0 
                        self.PortMap_recv[int(s1)-1][int(s2)-1]=0
                        self.PortMap_recv[int(s2)-1][int(s1)-1]=0 
                        self.Graph_plr[int(s1)-1][int(s2)-1]=0
                        self.Graph_plr[int(s2)-1][int(s1)-1]=0                         
                for dp in self.datapaths.values():
                    self._request_stats(dp)                
            except Exception as inst:     
                print("Exception=",inst)
     

    def calc_plr(self):
        switches = get_switch(self, None)
        links = get_link(self, None)            
        if len(switches)!=0 and len(links)!=0 :
            for x in range(len(self.PortMap_send)):
                for y in range(len(self.PortMap_send)):
                    if self.PortMap_send[x][y]!=0:
                        self.Graph_plr[x][y]=(self.PortMap_send[x][y]-self.PortMap_recv[y][x])/self.PortMap_send[x][y]
                    else:
                        self.Graph_plr[x][y]=0;

    def _request_stats(self, datapath):
        #self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def monitor_link_delay(self):
            try:
                links_list = get_link(self, None)
                mylinks=[(link.src.dpid,link.dst.dpid,link.src.port_no,link.dst.port_no) for link in links_list]
                self.topo_raw_switches=get_switch(self, None)
                if len(self.topo_raw_switches) > 0:
                    self.Graph_delay= [[0 for x in range(len(self.topo_raw_switches))] for y in range(len(self.topo_raw_switches))] 
                    for link in  links_list :
                        self.Graph_delay[int(link.src.dpid)-1][int(link.dst.dpid)-1]=0                     
                    for s1,s2,port1,port2 in mylinks:
                        self.send_del_packet(int(s1),port1)
            except Exception as inst:     
                print("Exception=",inst) 

    def send_del_packet(self, s_number, out_port):
        datapath = None #switch.dp        
        if len(self.topo_raw_switches) > 0:
            sws = get_switch(self, None)
            switches=[switch.dp for switch in sws]
            for s in switches:
                if int(s.id)==s_number:
                    datapath=s
        dpid = datapath.id
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_IP,dst=self.controller_mac,src=self.controller_mac))
        pkt.add_protocol(ipv4.ipv4(proto=in_proto.IPPROTO_ICMP,
                                   src=self.controller_ip,
                                   dst=self.controller_ip))
        echo_payl = '%d;%f' % (dpid, time.time())

        echo_payload = echo_payl.encode("utf-8")
        payload = icmp.echo(data=echo_payload)
        pkt.add_protocol(icmp.icmp(data=payload))
        pkt.serialize()             
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            data=pkt.data,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions
        )
        #self.logger.info("I am sending a packet %d and %d", s_number,out_port)        
        datapath.send_msg(out)  



    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        # The Function get_switch(self, None) outputs the list of switches.
        self.topo_raw_switches = copy.copy(get_switch(self, None))
        # The Function get_link(self, None) outputs the list of links.
        self.topo_raw_links = copy.copy(get_link(self, None))
        self.Graph_topo = [[0 for x in range(len(self.topo_raw_switches))] for y in range(len(self.topo_raw_switches))] 
        self.Graph_Cost = [[0 for x in range(len(self.topo_raw_switches))] for y in range(len(self.topo_raw_switches))] 
        #print("number of links=",len(self.topo_raw_links))                
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
            print("Exception: Be paitient till all switches have been known")
            
    @set_ev_cls(event.EventSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def handler_switch_leave(self, ev):
        self.logger.info("Not tracking Switches, switch leaved.")             

    def Link_Cost_Calc(self):
        try:
            switches = get_switch(self, None)
            links = get_link(self, None)  
            alpha=0.5
            if len(switches)!=0 and len(links)!=0 :
                for x in range(len(switches)):
                    for y in range(len(switches)):
                        self.Graph_Cost[x][y]=alpha*self.Graph_delay[x][y]+(1-alpha)*self.Graph_bw
        except:
            pass        
        

    def get_path (self,src,dst,first_port,final_port):

        #Dijkstra's algorithm

        #print ("get_path is called, src=",src," dst=",dst, " first_port=", first_port, " final_port=", final_port)

        distance = {}

        previous = {}

        sws = get_switch(self, None)
        switches=[switch.dp.id for switch in sws]

        for dpid in switches:

            distance[dpid] = float('Inf')

            previous[dpid] = None



        distance[src]=0


        Q=set(switches)
        #print(distance)

        while len(Q)>0:

            u = self.minimum_distance(distance, Q)
            if u==0 :
                return
            Q.remove(u)
            for p in switches:

                if self.Graph_topo[int(u)-1][int(p)-1]!=0:

                    w = self.Graph_Cost[int(u)-1][int(p)-1]

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
        print ("path from " ,src ," and " ,dst, " is=",r)
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

        #print ("install_path is called")
        sws = get_switch(self, None)
        switches=[switch.dp for switch in sws]
        datapath = switches[0] #initialization (not important:we should find relevant datapath)
        for sw, in_port, out_port in p:
            for s in switches:#find relevant datapath
                if int(s.id)==int(sw):
                    datapath=s

            ofproto = datapath.ofproto

            parser = datapath.ofproto_parser 

            #print (src_ip,"->", dst_ip, "via ", sw, " in_port=", in_port, " out_port=", out_port)


            match=parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)#,ipv4_src="10.0.0.3")

            actions=[parser.OFPActionOutput(out_port)]

            #datapath=switches[int(sw)-1]


            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS , actions)]

            mod = datapath.ofproto_parser.OFPFlowMod(

                     datapath=datapath, match=match, idle_timeout=0, hard_timeout=0,

                 priority=1, instructions=inst)

            datapath.send_msg(mod) 

    def install_path_withIP(self, p, src_ip, dst_ip):
        #print ("install_path_withIP is called ",src_ip," ",dst_ip, " " )
        sws = get_switch(self, None)
        switches=[switch.dp for switch in sws]
        datapath = switches[0] #initialization (not important:we should find relevant datapath)
        for sw, in_port, out_port in p:
            for s in switches:#find relevant datapath
                if int(s.id)==int(sw):
                    datapath=s

            ofproto = datapath.ofproto

            parser = datapath.ofproto_parser 

            #print (src_ip,"->", dst_ip, "via ", sw, " in_port=", in_port, " out_port=", out_port)


            match=parser.OFPMatch(in_port=in_port,  eth_type=0x0800, ipv4_src=str(src_ip), ipv4_dst=str(dst_ip))

            actions=[parser.OFPActionOutput(out_port)]                 

            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS , actions)]

            mod = datapath.ofproto_parser.OFPFlowMod(

                     datapath=datapath, match=match, idle_timeout=0, hard_timeout=0,

                 priority=500, instructions=inst)

            datapath.send_msg(mod)  
            
    def inform_and_install(self):
        hosts = get_host(self, None)
        """for host in hosts:
            self.logger.info("host=%s",host)"""

        switches = get_switch(self, None)
        """for s in switches:
            self.logger.info("switch=%s",s)  """                  

        #print("number of switches=",len(switches))
        links = get_link(self, None)
        #print("number of links=",len(links))                
        for link in links:
            self.Graph_topo[int(link.src.dpid)-1][int(link.dst.dpid)-1]=1 
        self.linkslist = [(link.src.dpid, link.dst.dpid, {'port': link.src.port_no}) for link in links]                    
        #self.logger.info("Links %s", self.linkslist) 
        links_list = get_link(self, None)
        mylinks=[(link.src.dpid,link.dst.dpid,link.src.port_no,link.dst.port_no) for link in links_list]
        for s1,s2,port1,port2 in mylinks:
            self.PortMap_topo[int(s1)-1][int(s2)-1]=port1
            self.PortMap_topo[int(s2)-1][int(s1)-1]=port2 
        #self.show_host_table()  
        self.topo_raw_switches=switches                  
        if len(switches)!=0 and len(links)!=0 :
            """for x in range(len(switches)):
                for y in range(len(switches)):
                    print(self.Graph_topo[x][y]," ",end=" ")
                print()
            for x in range(len(switches)):
                for y in range(len(switches)):
                    print(self.PortMap_topo[x][y]," ",end=" ")
                print() """
            for keys1,values1 in self.hosts.items():
                for keys2,values2 in self.hosts.items():
                    if keys1!=keys2:
                        #print(values1["mac"]," ",values2["mac"]," ",values1["port"]," ",values2["port"],keys1," ",keys2)
                        p=self.get_path(int(values1["dpid"]),int(values2["dpid"]),values1["port"],values2["port"])
                        if p!=None:
                            self.install_path_withIP(p,keys1,keys2)
                            #self.install_path_withmac(p,values1["mac"],values2["mac"])
                            #reverse path calculation
                        #print(values2["mac"]," ",values1["mac"]," ",values2["port"]," ",values1["port"],keys2," ",keys1)
                        p=self.get_path(int(values2["dpid"]),int(values1["dpid"]),values2["port"],values1["port"])
                        if p!=None:
                            self.install_path_withIP(p,keys2,keys1)
                            #self.install_path_withmac(p,values1["mac"],values2["mac"])                                                            

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """for p in ev.msg.body:
            self.logger.info('port_no=%d hw_addr=%s name=%s config=0x%08x '
                         'state=0x%08x curr=0x%08x advertised=0x%08x '
                         'supported=0x%08x peer=0x%08x curr_speed=%d '
                         'max_speed=%d' %
                         (p.port_no, p.hw_addr,
                          p.name, p.config,
                          p.state, p.curr, p.advertised,
                          p.supported, p.peer, p.curr_speed,
                          p.max_speed))"""
              
        switch = ev.msg.datapath
        for x in range(len(self.PortMap_topo)):
            for p in ev.msg.body:
                if int(p.port_no)==self.PortMap_topo[int(switch.id)-1][x]:     
                    self.Graph_bw[int(switch.id)-1][x] = p.curr_speed
                    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        """self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')"""

        for stat in sorted(body, key=attrgetter('port_no')):
            """self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)"""
            for x in range(len(self.PortMap_topo)):
                if int(stat.port_no)==self.PortMap_topo[int(ev.msg.datapath.id)-1][x]:
                    self.PortMap_send[int(ev.msg.datapath.id)-1][x]= stat.tx_packets
                    self.PortMap_recv[int(ev.msg.datapath.id)-1][x]= stat.rx_packets


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
        
    def expireHostEntries(self):
        expiredEntries = []
        for key,val in self.hosts.items():
            if int(time.time()) > val['timestamp'] + self.IDLE_TIMEOUT:
                expiredEntries.append(key)

        for ip in expiredEntries:
            del self.hosts[ip]

        Timer(self.IDLE_TIMEOUT, self.expireHostEntries).start()        

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


