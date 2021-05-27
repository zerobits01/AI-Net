from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from operator import attrgetter


#from ryu.ofproto import ofproto_v1_3

from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib import mac, hub
from ryu.topology import event, switches
import copy
from ryu.topology.api import get_switch, get_link
import time
from ryu.lib.packet import ethernet, ipv4, arp, ipv6, icmp
from ryu.lib.packet import ether_types, in_proto


class Link_Stat(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Link_Stat, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topo_raw_switches = []
        self.topo_raw_links = [] 
        self.datapaths = {}        
        self.Graph_delay=[]
        self.Graph_bw=[]
        self.Graph_plr=[]
        self.PortMap_topo=[]    
        self.PortMap_send=[]    
        self.PortMap_recv=[]    
        self.controller_mac = 'dd:dd:dd:dd:dd:dd' # decoy MAC
        self.controller_ip = '1.1.1.1' # decoy IP
        self.monitor_thread = hub.spawn(self.monitor_link_delay)	
        self.monitor_thread = hub.spawn(self.monitor_link_loss)	
        self.monitor_thread = hub.spawn(self.monitor_link_bw)	

    def show_delay(self):
        hub.sleep(1)# this delay is used to assure all packets have been received
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
    def show_bw(self):
        hub.sleep(1)# this delay is used to assure all packets have been received
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
                    print()     """          
        except:
            pass		                  

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return        
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

    def monitor_link_loss(self):
        while True:
            hub.sleep(2)        
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
            hub.sleep(3)#to make assure all stats have been received
            self.calc_plr()
            self.show_PLR()   
            
    def monitor_link_bw(self):
        while True:
            hub.sleep(2)        
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
            hub.sleep(2)#to make assure all stats have been received
            self.show_bw()               

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
        
    def _request_desc_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser    
        # Request port/link descriptions, useful for obtaining bandwidth
        req = parser.OFPPortDescStatsRequest(datapath)
        datapath.send_msg(req)
        
    def monitor_link_delay(self):
        while True:
            hub.sleep(1)        
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
            self.show_delay()

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


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        """
        self.logger.info('datapath         port     '
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


