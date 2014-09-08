# Copyright (C) 2014 VA Linux Systems Japan K.K.
# Copyright (C) 2014 Fumihiko Kakuma <kakuma at valinux co jp>
# Copyright (C) 2014 YAMAMOTO Takashi <yamamoto at valinux co jp>
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from ryu.app.ofctl import api as ryu_api
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import packet
from ryu.lib.packet import vlan

from neutron.common import log
from neutron.openstack.common.gettextutils import _LI
from neutron.openstack.common import log as logging
import neutron.plugins.ofagent.agent.metadata as meta


LOG = logging.getLogger(__name__)


class ArpLib(object):

    def __init__(self, ryuapp):
        """Constructor.

        Define the internal table mapped an ip and a mac in a network.
        self._arp_tbl:
            {network1: {ip_addr: mac, ...},
             network2: {ip_addr: mac, ...},
             ...,
            }

        :param ryuapp: object of the ryu app.
        """
        self.ryuapp = ryuapp
        self._arp_tbl = {}
        self.br = None

    def set_bridge(self, br):
        self.br = br

    @log.log
    def _send_arp_reply(self, datapath, port, pkt):
        ofp = datapath.ofproto
        ofpp = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [ofpp.OFPActionOutput(port=port)]
        out = ofpp.OFPPacketOut(datapath=datapath,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=ofp.OFPP_CONTROLLER,
                                actions=actions,
                                data=data)
        ryu_api.send_msg(self.ryuapp, out)

    @log.log
    def _send_unknown_packet(self, msg, in_port, out_port):
        datapath = msg.datapath
        ofp = datapath.ofproto
        ofpp = datapath.ofproto_parser
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        actions = [ofpp.OFPActionOutput(port=out_port)]
        out = ofpp.OFPPacketOut(datapath=datapath,
                                buffer_id=msg.buffer_id,
                                in_port=in_port,
                                actions=actions,
                                data=data)
        ryu_api.send_msg(self.ryuapp, out)

    def _respond_arp(self, datapath, port, arptbl,
                     pkt_ethernet, pkt_vlan, pkt_arp):
        if pkt_arp.opcode != arp.ARP_REQUEST:
            LOG.debug("unknown arp op %s", pkt_arp.opcode)
            return False
        ip_addr = pkt_arp.dst_ip
        hw_addr = arptbl.get(ip_addr)
        if hw_addr is None:
            LOG.debug("unknown arp request %s", ip_addr)
            return False
        LOG.debug("responding arp request %(ip_addr)s -> %(hw_addr)s",
                  {'ip_addr': ip_addr, 'hw_addr': hw_addr})
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=hw_addr))
        if pkt_vlan:
            pkt.add_protocol(vlan.vlan(cfi=pkt_vlan.cfi,
                                       ethertype=pkt_vlan.ethertype,
                                       pcp=pkt_vlan.pcp,
                                       vid=pkt_vlan.vid))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=hw_addr,
                                 src_ip=ip_addr,
                                 dst_mac=pkt_arp.src_mac,
                                 dst_ip=pkt_arp.src_ip))
        self._send_arp_reply(datapath, port, pkt)
        return True

    @log.log
    def add_arp_table_entry(self, network, ip, mac):
        if network in self._arp_tbl:
            self._arp_tbl[network][ip] = mac
        else:
            self._arp_tbl[network] = {ip: mac}

    @log.log
    def del_arp_table_entry(self, network, ip):
        del self._arp_tbl[network][ip]
        if not self._arp_tbl[network]:
            del self._arp_tbl[network]

    def packet_in_handler(self, ev):
        """Check a packet-in message.

           Build and output an arp reply if a packet-in message is
           an arp packet.
        """
        msg = ev.msg
        LOG.debug("packet-in msg %s", msg)
        datapath = msg.datapath
        if self.br is None:
            LOG.info(_LI("No bridge is set"))
            return
        if self.br.datapath.id != datapath.id:
            LOG.info(_LI("Unknown bridge %(dpid)s ours %(ours)s"),
                     {"dpid": datapath.id, "ours": self.br.datapath.id})
            return
        ofp = datapath.ofproto
        port = msg.match['in_port']
        metadata = msg.match.get('metadata')
        pkt = packet.Packet(msg.data)
        LOG.info(_LI("packet-in dpid %(dpid)s in_port %(port)s pkt %(pkt)s"),
                 {'dpid': dpid_lib.dpid_to_str(datapath.id),
                 'port': port, 'pkt': pkt})

        if metadata is None:
            LOG.info(_LI("drop non tenant packet"))
            return
        network = metadata & meta.NETWORK_MASK
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            LOG.info(_LI("drop non-ethernet packet"))
            return
        pkt_vlan = pkt.get_protocol(vlan.vlan)
        pkt_arp = pkt.get_protocol(arp.arp)
        if not pkt_arp:
            LOG.info(_LI("drop non-arp packet"))
            return

        arptbl = self._arp_tbl.get(network)
        if arptbl:
            if self._respond_arp(datapath, port, arptbl,
                                 pkt_ethernet, pkt_vlan, pkt_arp):
                return
        else:
            LOG.info(_LI("unknown network %s"), network)

        # add a flow to skip a packet-in to a controller.
        self.br.arp_passthrough(network=network, tpa=pkt_arp.dst_ip)
        # send an unknown arp packet to the table.
        self._send_unknown_packet(msg, port, ofp.OFPP_TABLE)
