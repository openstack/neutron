# Copyright (c) 2015 OpenStack Foundation.
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

import netaddr

from oslo_config import cfg
from oslo_log import log as logging
from sqlalchemy.orm import exc

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.common import utils
from neutron.db import common_db_mixin
from neutron.db import models_v2
from neutron.ipam import utils as ipam_utils

LOG = logging.getLogger(__name__)


class DbBasePluginCommon(common_db_mixin.CommonDbMixin):
    """Stores getters and helper methods for db_base_plugin_v2

    All private getters and simple helpers like _make_*_dict were moved from
    db_base_plugin_v2.
    More complicated logic and public methods left in db_base_plugin_v2.
    Main purpose of this class is to make getters accessible for Ipam
    backends.
    """

    @staticmethod
    def _generate_mac():
        return utils.get_random_mac(cfg.CONF.base_mac.split(':'))

    @staticmethod
    def _delete_ip_allocation(context, network_id, subnet_id, ip_address):

        # Delete the IP address from the IPAllocate table
        LOG.debug("Delete allocated IP %(ip_address)s "
                  "(%(network_id)s/%(subnet_id)s)",
                  {'ip_address': ip_address,
                   'network_id': network_id,
                   'subnet_id': subnet_id})
        context.session.query(models_v2.IPAllocation).filter_by(
            network_id=network_id,
            ip_address=ip_address,
            subnet_id=subnet_id).delete()

    @staticmethod
    def _store_ip_allocation(context, ip_address, network_id, subnet_id,
                             port_id):
        LOG.debug("Allocated IP %(ip_address)s "
                  "(%(network_id)s/%(subnet_id)s/%(port_id)s)",
                  {'ip_address': ip_address,
                   'network_id': network_id,
                   'subnet_id': subnet_id,
                   'port_id': port_id})
        allocated = models_v2.IPAllocation(
            network_id=network_id,
            port_id=port_id,
            ip_address=ip_address,
            subnet_id=subnet_id
        )
        context.session.add(allocated)

    @classmethod
    def _check_gateway_in_subnet(cls, cidr, gateway):
        """Validate that the gateway is on the subnet."""
        ip = netaddr.IPAddress(gateway)
        if ip.version == 4 or (ip.version == 6 and not ip.is_link_local()):
            return ipam_utils.check_subnet_ip(cidr, gateway)
        return True

    def _make_subnet_dict(self, subnet, fields=None):
        res = {'id': subnet['id'],
               'name': subnet['name'],
               'tenant_id': subnet['tenant_id'],
               'network_id': subnet['network_id'],
               'ip_version': subnet['ip_version'],
               'cidr': subnet['cidr'],
               'subnetpool_id': subnet.get('subnetpool_id'),
               'allocation_pools': [{'start': pool['first_ip'],
                                     'end': pool['last_ip']}
                                    for pool in subnet['allocation_pools']],
               'gateway_ip': subnet['gateway_ip'],
               'enable_dhcp': subnet['enable_dhcp'],
               'ipv6_ra_mode': subnet['ipv6_ra_mode'],
               'ipv6_address_mode': subnet['ipv6_address_mode'],
               'dns_nameservers': [dns['address']
                                   for dns in subnet['dns_nameservers']],
               'host_routes': [{'destination': route['destination'],
                                'nexthop': route['nexthop']}
                               for route in subnet['routes']],
               'shared': subnet['shared']
               }
        # Call auxiliary extend functions, if any
        self._apply_dict_extend_functions(attributes.SUBNETS, res, subnet)
        return self._fields(res, fields)

    def _make_subnetpool_dict(self, subnetpool, fields=None):
        default_prefixlen = str(subnetpool['default_prefixlen'])
        min_prefixlen = str(subnetpool['min_prefixlen'])
        max_prefixlen = str(subnetpool['max_prefixlen'])
        res = {'id': subnetpool['id'],
               'name': subnetpool['name'],
               'tenant_id': subnetpool['tenant_id'],
               'default_prefixlen': default_prefixlen,
               'min_prefixlen': min_prefixlen,
               'max_prefixlen': max_prefixlen,
               'shared': subnetpool['shared'],
               'prefixes': [prefix['cidr']
                            for prefix in subnetpool['prefixes']],
               'ip_version': subnetpool['ip_version'],
               'default_quota': subnetpool['default_quota']}
        return self._fields(res, fields)

    def _make_port_dict(self, port, fields=None,
                        process_extensions=True):
        res = {"id": port["id"],
               'name': port['name'],
               "network_id": port["network_id"],
               'tenant_id': port['tenant_id'],
               "mac_address": port["mac_address"],
               "admin_state_up": port["admin_state_up"],
               "status": port["status"],
               "fixed_ips": [{'subnet_id': ip["subnet_id"],
                              'ip_address': ip["ip_address"]}
                             for ip in port["fixed_ips"]],
               "device_id": port["device_id"],
               "device_owner": port["device_owner"]}
        # Call auxiliary extend functions, if any
        if process_extensions:
            self._apply_dict_extend_functions(
                attributes.PORTS, res, port)
        return self._fields(res, fields)

    def _get_network(self, context, id):
        try:
            network = self._get_by_id(context, models_v2.Network, id)
        except exc.NoResultFound:
            raise n_exc.NetworkNotFound(net_id=id)
        return network

    def _get_subnet(self, context, id):
        try:
            subnet = self._get_by_id(context, models_v2.Subnet, id)
        except exc.NoResultFound:
            raise n_exc.SubnetNotFound(subnet_id=id)
        return subnet

    def _get_subnetpool(self, context, id):
        try:
            return self._get_by_id(context, models_v2.SubnetPool, id)
        except exc.NoResultFound:
            raise n_exc.SubnetPoolNotFound(subnetpool_id=id)

    def _get_all_subnetpools(self, context):
        # NOTE(tidwellr): see note in _get_all_subnets()
        return context.session.query(models_v2.SubnetPool).all()

    def _get_port(self, context, id):
        try:
            port = self._get_by_id(context, models_v2.Port, id)
        except exc.NoResultFound:
            raise n_exc.PortNotFound(port_id=id)
        return port

    def _get_dns_by_subnet(self, context, subnet_id):
        dns_qry = context.session.query(models_v2.DNSNameServer)
        return dns_qry.filter_by(subnet_id=subnet_id).all()

    def _get_route_by_subnet(self, context, subnet_id):
        route_qry = context.session.query(models_v2.SubnetRoute)
        return route_qry.filter_by(subnet_id=subnet_id).all()

    def _get_router_gw_ports_by_network(self, context, network_id):
        port_qry = context.session.query(models_v2.Port)
        return port_qry.filter_by(network_id=network_id,
                device_owner=constants.DEVICE_OWNER_ROUTER_GW).all()

    def _get_subnets_by_network(self, context, network_id):
        subnet_qry = context.session.query(models_v2.Subnet)
        return subnet_qry.filter_by(network_id=network_id).all()

    def _get_subnets_by_subnetpool(self, context, subnetpool_id):
        subnet_qry = context.session.query(models_v2.Subnet)
        return subnet_qry.filter_by(subnetpool_id=subnetpool_id).all()

    def _get_all_subnets(self, context):
        # NOTE(salvatore-orlando): This query might end up putting
        # a lot of stress on the db. Consider adding a cache layer
        return context.session.query(models_v2.Subnet).all()

    def _make_network_dict(self, network, fields=None,
                           process_extensions=True):
        res = {'id': network['id'],
               'name': network['name'],
               'tenant_id': network['tenant_id'],
               'admin_state_up': network['admin_state_up'],
               'mtu': network.get('mtu', constants.DEFAULT_NETWORK_MTU),
               'status': network['status'],
               'shared': network['shared'],
               'subnets': [subnet['id']
                           for subnet in network['subnets']]}
        # TODO(pritesh): Move vlan_transparent to the extension module.
        # vlan_transparent here is only added if the vlantransparent
        # extension is enabled.
        if ('vlan_transparent' in network and network['vlan_transparent'] !=
            attributes.ATTR_NOT_SPECIFIED):
            res['vlan_transparent'] = network['vlan_transparent']
        # Call auxiliary extend functions, if any
        if process_extensions:
            self._apply_dict_extend_functions(
                attributes.NETWORKS, res, network)
        return self._fields(res, fields)

    def _make_subnet_args(self, context, shared, detail,
                          subnet, subnetpool_id=None):
        args = {'tenant_id': detail.tenant_id,
                'id': detail.subnet_id,
                'name': subnet['name'],
                'network_id': subnet['network_id'],
                'ip_version': subnet['ip_version'],
                'cidr': str(detail.subnet_cidr),
                'subnetpool_id': subnetpool_id,
                'enable_dhcp': subnet['enable_dhcp'],
                'gateway_ip': self._gateway_ip_str(subnet, detail.subnet_cidr),
                'shared': shared}
        if subnet['ip_version'] == 6 and subnet['enable_dhcp']:
            if attributes.is_attr_set(subnet['ipv6_ra_mode']):
                args['ipv6_ra_mode'] = subnet['ipv6_ra_mode']
            if attributes.is_attr_set(subnet['ipv6_address_mode']):
                args['ipv6_address_mode'] = subnet['ipv6_address_mode']
        return args

    def _make_fixed_ip_dict(self, ips):
        # Excludes from dict all keys except subnet_id and ip_address
        return [{'subnet_id': ip["subnet_id"],
                 'ip_address': ip["ip_address"]}
                for ip in ips]

    def _gateway_ip_str(self, subnet, cidr_net):
        if subnet.get('gateway_ip') is attributes.ATTR_NOT_SPECIFIED:
                return str(cidr_net.network + 1)
        return subnet.get('gateway_ip')
