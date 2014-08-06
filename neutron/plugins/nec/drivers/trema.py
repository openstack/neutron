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

from neutron.openstack.common import uuidutils
from neutron.plugins.nec.common import ofc_client
from neutron.plugins.nec import ofc_driver_base


class TremaDriverBase(ofc_driver_base.OFCDriverBase):
    """Common class for Trema (Sliceable Switch) Drivers."""
    networks_path = "/networks"
    network_path = "/networks/%s"

    router_supported = False

    def __init__(self, conf_ofc):
        # Trema sliceable REST API does not support HTTPS
        self.client = ofc_client.OFCClient(host=conf_ofc.host,
                                           port=conf_ofc.port)

    def _get_network_id(self, ofc_network_id):
        # ofc_network_id : /networks/<network-id>
        return ofc_network_id.split('/')[2]

    def _get_tenant_id(self, tenant_id):
        # Trema does not use tenant_id, but it returns
        # /tenants/<tenant_id> format to keep consistency with PFC driver.
        return '/tenants/' + tenant_id

    def create_tenant(self, description, tenant_id=None):
        return self._get_tenant_id(tenant_id or uuidutils.generate_uuid())

    def update_tenant(self, ofc_tenant_id, description):
        pass

    def delete_tenant(self, ofc_tenant_id):
        pass

    def create_network(self, ofc_tenant_id, description, network_id=None):
        ofc_network_id = network_id or uuidutils.generate_uuid()
        body = {'id': ofc_network_id, 'description': description}
        self.client.post(self.networks_path, body=body)
        return self.network_path % ofc_network_id

    def delete_network(self, ofc_network_id):
        return self.client.delete(ofc_network_id)


class TremaFilterDriverMixin(object):
    """Trema (Sliceable Switch) PacketFilter Driver Mixin."""
    filters_path = "/filters"
    filter_path = "/filters/%s"

    @classmethod
    def filter_supported(cls):
        return True

    def create_filter(self, ofc_network_id, filter_dict,
                      portinfo=None, filter_id=None, apply_ports=None):
        if filter_dict['action'].upper() in ["ACCEPT", "ALLOW"]:
            ofc_action = "ALLOW"
        elif filter_dict['action'].upper() in ["DROP", "DENY"]:
            ofc_action = "DENY"

        body = {'priority': filter_dict['priority'],
                'slice': self._get_network_id(ofc_network_id),
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
            if filter_dict['protocol'].upper() == "ICMP":
                body['dl_type'] = "0x800"
                body['nw_proto'] = hex(1)
            elif filter_dict['protocol'].upper() == "TCP":
                body['dl_type'] = "0x800"
                body['nw_proto'] = hex(6)
            elif filter_dict['protocol'].upper() == "UDP":
                body['dl_type'] = "0x800"
                body['nw_proto'] = hex(17)
            elif filter_dict['protocol'].upper() == "ARP":
                body['dl_type'] = "0x806"
                ofp_wildcards.append("nw_proto")
            else:
                body['nw_proto'] = filter_dict['protocol']
        else:
            ofp_wildcards.append("nw_proto")

        if 'dl_type' in body:
            pass
        elif filter_dict['eth_type']:
            body['dl_type'] = filter_dict['eth_type']
        else:
            ofp_wildcards.append("dl_type")

        if filter_dict['src_port']:
            body['tp_src'] = hex(filter_dict['src_port'])
        else:
            ofp_wildcards.append("tp_src")

        if filter_dict['dst_port']:
            body['tp_dst'] = hex(filter_dict['dst_port'])
        else:
            ofp_wildcards.append("tp_dst")

        ofc_filter_id = filter_id or uuidutils.generate_uuid()
        body['id'] = ofc_filter_id

        body['ofp_wildcards'] = ','.join(ofp_wildcards)

        self.client.post(self.filters_path, body=body)
        return self.filter_path % ofc_filter_id

    def delete_filter(self, ofc_filter_id):
        return self.client.delete(ofc_filter_id)


class TremaPortBaseDriver(TremaDriverBase, TremaFilterDriverMixin):
    """Trema (Sliceable Switch) Driver for port base binding.

    TremaPortBaseDriver uses port base binding.
    Ports are identified by datapath_id, port_no and vlan_id.
    """
    ports_path = "%(network)s/ports"
    port_path = "%(network)s/ports/%(port)s"

    def create_port(self, ofc_network_id, portinfo,
                    port_id=None, filters=None):
        ofc_port_id = port_id or uuidutils.generate_uuid()
        path = self.ports_path % {'network': ofc_network_id}
        body = {'id': ofc_port_id,
                'datapath_id': portinfo.datapath_id,
                'port': str(portinfo.port_no),
                'vid': str(portinfo.vlan_id)}
        self.client.post(path, body=body)
        return self.port_path % {'network': ofc_network_id,
                                 'port': ofc_port_id}

    def delete_port(self, ofc_port_id):
        return self.client.delete(ofc_port_id)


class TremaPortMACBaseDriver(TremaDriverBase, TremaFilterDriverMixin):
    """Trema (Sliceable Switch) Driver for port-mac base binding.

    TremaPortBaseDriver uses port-mac base binding.
    Ports are identified by datapath_id, port_no, vlan_id and mac.
    """
    ports_path = "%(network)s/ports"
    port_path = "%(network)s/ports/%(port)s"
    attachments_path = "%(network)s/ports/%(port)s/attachments"
    attachment_path = "%(network)s/ports/%(port)s/attachments/%(attachment)s"

    def create_port(self, ofc_network_id, portinfo, port_id=None,
                    filters=None):
        #NOTE: This Driver create slices with Port-MAC Based bindings on Trema
        #      Sliceable.  It's REST API requires Port Based binding before you
        #      define Port-MAC Based binding.
        ofc_port_id = port_id or uuidutils.generate_uuid()
        dummy_port_id = "dummy-%s" % ofc_port_id

        path = self.ports_path % {'network': ofc_network_id}
        body = {'id': dummy_port_id,
                'datapath_id': portinfo.datapath_id,
                'port': str(portinfo.port_no),
                'vid': str(portinfo.vlan_id)}
        self.client.post(path, body=body)

        path = self.attachments_path % {'network': ofc_network_id,
                                        'port': dummy_port_id}
        body = {'id': ofc_port_id, 'mac': portinfo.mac}
        self.client.post(path, body=body)

        path = self.port_path % {'network': ofc_network_id,
                                 'port': dummy_port_id}
        self.client.delete(path)

        return self.attachment_path % {'network': ofc_network_id,
                                       'port': dummy_port_id,
                                       'attachment': ofc_port_id}

    def delete_port(self, ofc_port_id):
        return self.client.delete(ofc_port_id)


class TremaMACBaseDriver(TremaDriverBase):
    """Trema (Sliceable Switch) Driver for mac base binding.

    TremaPortBaseDriver uses mac base binding.
    Ports are identified by mac.
    """
    attachments_path = "%(network)s/attachments"
    attachment_path = "%(network)s/attachments/%(attachment)s"

    @classmethod
    def filter_supported(cls):
        return False

    def create_port(self, ofc_network_id, portinfo, port_id=None,
                    filters=None):
        ofc_port_id = port_id or uuidutils.generate_uuid()
        path = self.attachments_path % {'network': ofc_network_id}
        body = {'id': ofc_port_id, 'mac': portinfo.mac}
        self.client.post(path, body=body)
        return self.attachment_path % {'network': ofc_network_id,
                                       'attachment': ofc_port_id}

    def delete_port(self, ofc_port_id):
        return self.client.delete(ofc_port_id)
