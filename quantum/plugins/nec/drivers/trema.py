# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

import uuid

from quantum.plugins.nec.common import ofc_client
from quantum.plugins.nec import ofc_driver_base


class TremaDriverBase(ofc_driver_base.OFCDriverBase):
    """Common class for Trema (Sliceable Switch) Drivers"""
    networks_path = "/networks"
    network_path = "/networks/%s"

    def __init__(self, conf_ofc):
        # Trema sliceable REST API does not support HTTPS
        self.client = ofc_client.OFCClient(host=conf_ofc.host,
                                           port=conf_ofc.port)

    def create_tenant(self, description, tenant_id=None):
        return tenant_id or str(uuid.uuid4())

    def update_tenant(self, ofc_tenant_id, description):
        pass

    def delete_tenant(self, ofc_tenant_id):
        pass

    def create_network(self, ofc_tenant_id, description, network_id=None):
        ofc_network_id = network_id or str(uuid.uuid4())
        body = {'id': ofc_network_id, 'description': description}
        self.client.post(self.networks_path, body=body)
        return ofc_network_id

    def update_network(self, ofc_tenant_id, ofc_network_id, description):
        path = self.network_path % ofc_network_id
        body = {'description': description}
        return self.client.put(path, body=body)

    def delete_network(self, ofc_tenant_id, ofc_network_id):
        path = self.network_path % ofc_network_id
        return self.client.delete(path)

    def update_port(self, ofc_tenant_id, ofc_network_id, ofc_port_id,
                    portinfo):
        self.delete_port(ofc_tenant_id, ofc_network_id, ofc_port_id)
        self.create_port(ofc_tenant_id, ofc_network_id, portinfo, ofc_port_id)


class TremaFilterDriver(object):
    """Trema (Sliceable Switch) PacketFilter Driver"""
    filters_path = "/filters"
    filter_path = "/filters/%s"

    @classmethod
    def filter_supported(cls):
        return True

    def create_filter(self, ofc_tenant_id, ofc_network_id, filter_dict,
                      portinfo=None, filter_id=None):
        if filter_dict['action'].upper() in ["ACCEPT", "ALLOW"]:
            ofc_action = "ALLOW"
        elif filter_dict['action'].upper() in ["DROP", "DENY"]:
            ofc_action = "DENY"

        body = {'priority': filter_dict['priority'],
                'slice': ofc_network_id,
                'action': ofc_action}
        ofp_wildcards = ["dl_vlan", "dl_vlan_pcp", "nw_tos"]

        if portinfo:
            body['in_datapath_id'] = portinfo.datapath_id
            body['in_port'] = portinfo.port_no
        else:
            body['wildcards'] = "in_datapath_id"
            ofp_wildcards.append("in_port")

        if filter_dict['src_mac']:
            body['dl_src'] = filter_dict['src_mac']
        else:
            ofp_wildcards.append("dl_src")

        if filter_dict['dst_mac']:
            body['dl_dst'] = filter_dict['dst_mac']
        else:
            ofp_wildcards.append("dl_dst")

        if filter_dict['src_cidr']:
            body['nw_src'] = filter_dict['src_cidr']
        else:
            ofp_wildcards.append("nw_src:32")

        if filter_dict['dst_cidr']:
            body['nw_dst'] = filter_dict['dst_cidr']
        else:
            ofp_wildcards.append("nw_dst:32")

        if filter_dict['protocol']:
            if filter_dict['protocol'].upper() in "ICMP":
                body['dl_type'] = "0x800"
                body['nw_proto'] = hex(1)
            elif filter_dict['protocol'].upper() in "TCP":
                body['dl_type'] = "0x800"
                body['nw_proto'] = hex(6)
            elif filter_dict['protocol'].upper() in "UDP":
                body['dl_type'] = "0x800"
                body['nw_proto'] = hex(17)
            elif filter_dict['protocol'].upper() in "ARP":
                body['dl_type'] = "0x806"
                ofp_wildcards.append("nw_proto")
            else:
                body['nw_proto'] = filter_dict['protocol']
                if filter_dict['eth_type']:
                    body['dl_type'] = filter_dict['eth_type']
                else:
                    ofp_wildcards.append("dl_type")
        else:
            ofp_wildcards.append("dl_type")
            ofp_wildcards.append("nw_proto")

        if filter_dict['src_port']:
            body['tp_src'] = hex(filter_dict['src_port'])
        else:
            ofp_wildcards.append("tp_src")

        if filter_dict['dst_port']:
            body['tp_dst'] = hex(filter_dict['dst_port'])
        else:
            ofp_wildcards.append("tp_dst")

        ofc_filter_id = filter_id or str(uuid.uuid4())
        body['id'] = ofc_filter_id

        body['ofp_wildcards'] = ','.join(ofp_wildcards)

        self.client.post(self.filters_path, body=body)
        return ofc_filter_id

    def delete_filter(self, ofc_tenant_id, ofc_network_id, ofc_filter_id):
        path = self.filter_path % ofc_filter_id
        return self.client.delete(path)


class TremaPortBaseDriver(TremaDriverBase, TremaFilterDriver):
    """Trema (Sliceable Switch) Driver for port base binding

    TremaPortBaseDriver uses port base binding.
    Ports are identified by datapath_id, port_no and vlan_id.
    """
    ports_path = "/networks/%s/ports"
    port_path = "/networks/%s/ports/%s"

    def create_port(self, ofc_tenant_id, ofc_network_id, portinfo,
                    port_id=None):
        ofc_port_id = port_id or str(uuid.uuid4())
        path = self.ports_path % ofc_network_id
        body = {'id': ofc_port_id,
                'datapath_id': portinfo.datapath_id,
                'port': str(portinfo.port_no),
                'vid': str(portinfo.vlan_id)}
        self.client.post(path, body=body)
        return ofc_port_id

    def delete_port(self, ofc_tenant_id, ofc_network_id, ofc_port_id):
        path = self.port_path % (ofc_network_id, ofc_port_id)
        return self.client.delete(path)


class TremaPortMACBaseDriver(TremaDriverBase, TremaFilterDriver):
    """Trema (Sliceable Switch) Driver for port-mac base binding

    TremaPortBaseDriver uses port-mac base binding.
    Ports are identified by datapath_id, port_no, vlan_id and mac.
    """
    ports_path = "/networks/%s/ports"
    port_path = "/networks/%s/ports/%s"
    attachments_path = "/networks/%s/ports/%s/attachments"
    attachment_path = "/networks/%s/ports/%s/attachments/%s"

    def create_port(self, ofc_tenant_id, ofc_network_id, portinfo,
                    port_id=None):
        #NOTE: This Driver create slices with Port-MAC Based bindings on Trema
        #      Sliceable.  It's REST API requires Port Based binding before you
        #      define Port-MAC Based binding.
        ofc_port_id = port_id or str(uuid.uuid4())
        dummy_port_id = "dummy-%s" % ofc_port_id

        path = self.ports_path % ofc_network_id
        body = {'id': dummy_port_id,
                'datapath_id': portinfo.datapath_id,
                'port': str(portinfo.port_no),
                'vid': str(portinfo.vlan_id)}
        self.client.post(path, body=body)

        path = self.attachments_path % (ofc_network_id, dummy_port_id)
        body = {'id': ofc_port_id, 'mac': portinfo.mac}
        self.client.post(path, body=body)

        path = self.port_path % (ofc_network_id, dummy_port_id)
        self.client.delete(path)

        return ofc_port_id

    def delete_port(self, ofc_tenant_id, ofc_network_id, ofc_port_id):
        dummy_port_id = "dummy-%s" % ofc_port_id
        path = self.attachment_path % (ofc_network_id, dummy_port_id,
                                       ofc_port_id)
        return self.client.delete(path)


class TremaMACBaseDriver(TremaDriverBase):
    """Trema (Sliceable Switch) Driver for mac base binding

    TremaPortBaseDriver uses mac base binding.
    Ports are identified by mac.
    """
    attachments_path = "/networks/%s/attachments"
    attachment_path = "/networks/%s/attachments/%s"

    @classmethod
    def filter_supported(cls):
        return False

    def create_port(self, ofc_tenant_id, ofc_network_id, portinfo,
                    port_id=None):
        ofc_port_id = port_id or str(uuid.uuid4())
        path = self.attachments_path % ofc_network_id
        body = {'id': ofc_port_id, 'mac': portinfo.mac}
        self.client.post(path, body=body)
        return ofc_port_id

    def delete_port(self, ofc_tenant_id, ofc_network_id, ofc_port_id):
        path = self.attachment_path % (ofc_network_id, ofc_port_id)
        return self.client.delete(path)
