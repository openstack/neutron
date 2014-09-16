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

import re
import uuid

import netaddr

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as qexc
from neutron.common import log as call_log
from neutron import manager
from neutron.plugins.nec.common import ofc_client
from neutron.plugins.nec.extensions import packetfilter as ext_pf
from neutron.plugins.nec import ofc_driver_base


class InvalidOFCIdFormat(qexc.NeutronException):
    message = _("OFC %(resource)s ID has an invalid format: %(ofc_id)s")


class PFCDriverBase(ofc_driver_base.OFCDriverBase):
    """Base Class for PDC Drivers.

    PFCDriverBase provides methods to handle PFC resources through REST API.
    This uses ofc resource path instead of ofc resource ID.

    The class implements the API for PFC V4.0 or later.
    """

    router_supported = False

    match_ofc_network_id = re.compile(
        "^/tenants/(?P<tenant_id>[^/]+)/networks/(?P<network_id>[^/]+)$")
    match_ofc_port_id = re.compile(
        "^/tenants/(?P<tenant_id>[^/]+)/networks/(?P<network_id>[^/]+)"
        "/ports/(?P<port_id>[^/]+)$")

    def __init__(self, conf_ofc):
        self.client = ofc_client.OFCClient(host=conf_ofc.host,
                                           port=conf_ofc.port,
                                           use_ssl=conf_ofc.use_ssl,
                                           key_file=conf_ofc.key_file,
                                           cert_file=conf_ofc.cert_file,
                                           insecure_ssl=conf_ofc.insecure_ssl)

    @classmethod
    def filter_supported(cls):
        return False

    def _generate_pfc_str(self, raw_str):
        """Generate PFC acceptable String."""
        return re.sub(r'[^0-9a-zA-Z]', '_', raw_str)

    def _generate_pfc_id(self, id_str):
        """Generate ID on PFC.

        Currently, PFC ID must be less than 32.
        Shorten UUID string length from 36 to 31 by follows:
          * delete UUID Version and hyphen (see RFC4122)
          * ensure str length
        """
        try:
            # openstack.common.uuidutils.is_uuid_like() returns
            # False for KeyStone tenant_id, so uuid.UUID is used
            # directly here to accept tenant_id as UUID string
            uuid_str = str(uuid.UUID(id_str)).replace('-', '')
            uuid_no_version = uuid_str[:12] + uuid_str[13:]
            return uuid_no_version[:31]
        except Exception:
            return self._generate_pfc_str(id_str)[:31]

    def _generate_pfc_description(self, desc):
        """Generate Description on PFC.

        Currently, PFC Description must be less than 128.
        """
        return self._generate_pfc_str(desc)[:127]

    def _extract_ofc_network_id(self, ofc_network_id):
        match = self.match_ofc_network_id.match(ofc_network_id)
        if match:
            return match.group('network_id')
        raise InvalidOFCIdFormat(resource='network', ofc_id=ofc_network_id)

    def _extract_ofc_port_id(self, ofc_port_id):
        match = self.match_ofc_port_id.match(ofc_port_id)
        if match:
            return {'tenant': match.group('tenant_id'),
                    'network': match.group('network_id'),
                    'port': match.group('port_id')}
        raise InvalidOFCIdFormat(resource='port', ofc_id=ofc_port_id)

    def create_tenant(self, description, tenant_id=None):
        ofc_tenant_id = self._generate_pfc_id(tenant_id)
        body = {'id': ofc_tenant_id}
        self.client.post('/tenants', body=body)
        return '/tenants/' + ofc_tenant_id

    def delete_tenant(self, ofc_tenant_id):
        return self.client.delete(ofc_tenant_id)

    def create_network(self, ofc_tenant_id, description, network_id=None):
        path = "%s/networks" % ofc_tenant_id
        pfc_desc = self._generate_pfc_description(description)
        body = {'description': pfc_desc}
        res = self.client.post(path, body=body)
        ofc_network_id = res['id']
        return path + '/' + ofc_network_id

    def delete_network(self, ofc_network_id):
        return self.client.delete(ofc_network_id)

    def create_port(self, ofc_network_id, portinfo,
                    port_id=None, filters=None):
        path = "%s/ports" % ofc_network_id
        body = {'datapath_id': portinfo.datapath_id,
                'port': str(portinfo.port_no),
                'vid': str(portinfo.vlan_id)}
        if self.filter_supported() and filters:
            body['filters'] = [self._extract_ofc_filter_id(pf[1])
                               for pf in filters]
        res = self.client.post(path, body=body)
        ofc_port_id = res['id']
        return path + '/' + ofc_port_id

    def delete_port(self, ofc_port_id):
        return self.client.delete(ofc_port_id)


class PFCFilterDriverMixin(object):
    """PFC PacketFilter Driver Mixin."""
    filters_path = "/filters"
    filter_path = "/filters/%s"

    # PFC specific constants
    MIN_PRIORITY = 1
    MAX_PRIORITY = 32766
    CREATE_ONLY_FIELDS = ['action', 'priority']
    PFC_ALLOW_ACTION = "pass"
    PFC_DROP_ACTION = "drop"

    match_ofc_filter_id = re.compile("^/filters/(?P<filter_id>[^/]+)$")

    @classmethod
    def filter_supported(cls):
        return True

    def _set_param(self, filter_dict, body, key, create, convert_to=None):
        if key in filter_dict:
            if filter_dict[key]:
                if convert_to:
                    body[key] = convert_to(filter_dict[key])
                else:
                    body[key] = filter_dict[key]
            elif not create:
                body[key] = ""

    def _generate_body(self, filter_dict, apply_ports=None, create=True):
        body = {}

        if create:
            # action : pass, drop (mandatory)
            if filter_dict['action'].lower() in ext_pf.ALLOW_ACTIONS:
                body['action'] = self.PFC_ALLOW_ACTION
            else:
                body['action'] = self.PFC_DROP_ACTION
            # priority : mandatory
            body['priority'] = filter_dict['priority']

        for key in ['src_mac', 'dst_mac', 'src_port', 'dst_port']:
            self._set_param(filter_dict, body, key, create)

        for key in ['src_cidr', 'dst_cidr']:
            # CIDR must contain netmask even if it is an address.
            convert_to = lambda x: str(netaddr.IPNetwork(x))
            self._set_param(filter_dict, body, key, create, convert_to)

        # protocol : decimal (0-255)
        if 'protocol' in filter_dict:
            if (not filter_dict['protocol'] or
                # In the case of ARP, ip_proto should be set to wildcard.
                # eth_type is set during adding an entry to DB layer.
                filter_dict['protocol'].lower() == ext_pf.PROTO_NAME_ARP):
                if not create:
                    body['protocol'] = ""
            elif filter_dict['protocol'].lower() == constants.PROTO_NAME_ICMP:
                body['protocol'] = constants.PROTO_NUM_ICMP
            elif filter_dict['protocol'].lower() == constants.PROTO_NAME_TCP:
                body['protocol'] = constants.PROTO_NUM_TCP
            elif filter_dict['protocol'].lower() == constants.PROTO_NAME_UDP:
                body['protocol'] = constants.PROTO_NUM_UDP
            else:
                body['protocol'] = int(filter_dict['protocol'], 0)

        # eth_type : hex (0x0-0xFFFF)
        self._set_param(filter_dict, body, 'eth_type', create, hex)

        # apply_ports
        if apply_ports:
            # each element of apply_ports is a tuple of (neutron_id, ofc_id),
            body['apply_ports'] = []
            for p in apply_ports:
                try:
                    body['apply_ports'].append(self._extract_ofc_port_id(p[1]))
                except InvalidOFCIdFormat:
                    pass

        return body

    def _validate_filter_common(self, filter_dict):
        # Currently PFC support only IPv4 CIDR.
        for field in ['src_cidr', 'dst_cidr']:
            if (not filter_dict.get(field) or
                filter_dict[field] == attributes.ATTR_NOT_SPECIFIED):
                continue
            net = netaddr.IPNetwork(filter_dict[field])
            if net.version != 4:
                raise ext_pf.PacketFilterIpVersionNonSupported(
                    version=net.version, field=field, value=filter_dict[field])
        if ('priority' in filter_dict and
            not (self.MIN_PRIORITY <= filter_dict['priority']
                 <= self.MAX_PRIORITY)):
            raise ext_pf.PacketFilterInvalidPriority(
                min=self.MIN_PRIORITY, max=self.MAX_PRIORITY)

    def _validate_duplicate_priority(self, context, filter_dict):
        plugin = manager.NeutronManager.get_plugin()
        filters = {'network_id': [filter_dict['network_id']],
                   'priority': [filter_dict['priority']]}
        ret = plugin.get_packet_filters(context, filters=filters,
                                        fields=['id'])
        if ret:
            raise ext_pf.PacketFilterDuplicatedPriority(
                priority=filter_dict['priority'])

    def validate_filter_create(self, context, filter_dict):
        self._validate_filter_common(filter_dict)
        self._validate_duplicate_priority(context, filter_dict)

    def validate_filter_update(self, context, filter_dict):
        for field in self.CREATE_ONLY_FIELDS:
            if field in filter_dict:
                raise ext_pf.PacketFilterUpdateNotSupported(field=field)
        self._validate_filter_common(filter_dict)

    @call_log.log
    def create_filter(self, ofc_network_id, filter_dict,
                      portinfo=None, filter_id=None, apply_ports=None):
        body = self._generate_body(filter_dict, apply_ports, create=True)
        res = self.client.post(self.filters_path, body=body)
        # filter_id passed from a caller is not used.
        # ofc_filter_id is generated by PFC because the prefix of
        # filter_id has special meaning and it is internally used.
        ofc_filter_id = res['id']
        return self.filter_path % ofc_filter_id

    @call_log.log
    def update_filter(self, ofc_filter_id, filter_dict):
        body = self._generate_body(filter_dict, create=False)
        self.client.put(ofc_filter_id, body)

    @call_log.log
    def delete_filter(self, ofc_filter_id):
        return self.client.delete(ofc_filter_id)

    def _extract_ofc_filter_id(self, ofc_filter_id):
        match = self.match_ofc_filter_id.match(ofc_filter_id)
        if match:
            return match.group('filter_id')
        raise InvalidOFCIdFormat(resource='filter', ofc_id=ofc_filter_id)

    def convert_ofc_filter_id(self, context, ofc_filter_id):
        # PFC Packet Filter is supported after the format of mapping tables
        # are changed, so it is enough just to return ofc_filter_id
        return ofc_filter_id


class PFCRouterDriverMixin(object):

    router_supported = True
    router_nat_supported = False

    def create_router(self, ofc_tenant_id, router_id, description):
        path = '%s/routers' % ofc_tenant_id
        res = self.client.post(path, body=None)
        ofc_router_id = res['id']
        return path + '/' + ofc_router_id

    def delete_router(self, ofc_router_id):
        return self.client.delete(ofc_router_id)

    def add_router_interface(self, ofc_router_id, ofc_net_id,
                             ip_address=None, mac_address=None):
        # ip_address : <ip_address>/<netmask> (e.g., 10.0.0.0/24)
        path = '%s/interfaces' % ofc_router_id
        body = {'net_id': self._extract_ofc_network_id(ofc_net_id)}
        if ip_address:
            body['ip_address'] = ip_address
        if mac_address:
            body['mac_address'] = mac_address
        res = self.client.post(path, body=body)
        return path + '/' + res['id']

    def update_router_interface(self, ofc_router_inf_id,
                                ip_address=None, mac_address=None):
        # ip_address : <ip_address>/<netmask> (e.g., 10.0.0.0/24)
        if not ip_address and not mac_address:
            return
        body = {}
        if ip_address:
            body['ip_address'] = ip_address
        if mac_address:
            body['mac_address'] = mac_address
        return self.client.put(ofc_router_inf_id, body=body)

    def delete_router_interface(self, ofc_router_inf_id):
        return self.client.delete(ofc_router_inf_id)

    def list_router_routes(self, ofc_router_id):
        path = '%s/routes' % ofc_router_id
        ret = self.client.get(path)
        # Prepend ofc_router_id to route_id
        for r in ret['routes']:
            r['id'] = ofc_router_id + '/routes/' + r['id']
        return ret['routes']

    def add_router_route(self, ofc_router_id, destination, nexthop):
        path = '%s/routes' % ofc_router_id
        body = {'destination': destination,
                'nexthop': nexthop}
        ret = self.client.post(path, body=body)
        return path + '/' + ret['id']

    def delete_router_route(self, ofc_router_route_id):
        return self.client.delete(ofc_router_route_id)


class PFCV3Driver(PFCDriverBase):

    def create_tenant(self, description, tenant_id):
        ofc_tenant_id = self._generate_pfc_id(tenant_id)
        return "/tenants/" + ofc_tenant_id

    def delete_tenant(self, ofc_tenant_id):
        pass


class PFCV4Driver(PFCDriverBase):
    pass


class PFCV5Driver(PFCRouterDriverMixin, PFCDriverBase):
    pass


class PFCV51Driver(PFCFilterDriverMixin, PFCV5Driver):
    pass
