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

import functools

import netaddr

from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.api.definitions import subnetpool as subnetpool_def
from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib.db import api as db_api
from neutron_lib.db import model_query
from neutron_lib.db import resource_extend
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions
from neutron_lib.utils import net
from oslo_config import cfg
from oslo_log import log as logging
from sqlalchemy.orm import exc

from neutron.db import models_v2
from neutron.objects import base as base_obj
from neutron.objects import ports as port_obj
from neutron.objects import subnet as subnet_obj
from neutron.objects import subnetpool as subnetpool_obj

LOG = logging.getLogger(__name__)


def convert_result_to_dict(f):
    @functools.wraps(f)
    def inner(*args, **kwargs):
        result = f(*args, **kwargs)

        if result is None:
            return None
        elif isinstance(result, list):
            return [r.to_dict() for r in result]
        else:
            return result.to_dict()
    return inner


def filter_fields(f):
    @functools.wraps(f)
    def inner_filter(*args, **kwargs):
        result = f(*args, **kwargs)
        fields = kwargs.get('fields')
        if not fields:
            try:
                pos = f.__code__.co_varnames.index('fields')
                fields = args[pos]
            except (IndexError, ValueError):
                return result

        do_filter = lambda d: {k: v for k, v in d.items() if k in fields}
        if isinstance(result, list):
            return [do_filter(obj) for obj in result]
        else:
            return do_filter(result)
    return inner_filter


def make_result_with_fields(f):
    @functools.wraps(f)
    def inner(*args, **kwargs):
        fields = kwargs.get('fields')
        result = f(*args, **kwargs)
        if fields is None:
            return result
        elif isinstance(result, list):
            return [db_utils.resource_fields(r, fields) for r in result]
        else:
            return db_utils.resource_fields(result, fields)

    return inner


class DbBasePluginCommon(object):
    """Stores getters and helper methods for db_base_plugin_v2

    All private getters and simple helpers like _make_*_dict were moved from
    db_base_plugin_v2.
    More complicated logic and public methods left in db_base_plugin_v2.
    Main purpose of this class is to make getters accessible for Ipam
    backends.
    """

    @staticmethod
    def _generate_macs(mac_count=1):
        mac_maker = net.random_mac_generator(cfg.CONF.base_mac.split(':'))
        return [next(mac_maker) for x in range(mac_count)]

    @db_api.CONTEXT_READER
    def _is_mac_in_use(self, context, network_id, mac_address):
        return port_obj.Port.objects_exist(context, network_id=network_id,
                                           mac_address=mac_address)

    @staticmethod
    def _delete_ip_allocation(context, network_id, subnet_id, ip_address):

        # Delete the IP address from the IPAllocate table
        LOG.debug("Delete allocated IP %(ip_address)s "
                  "(%(network_id)s/%(subnet_id)s)",
                  {'ip_address': ip_address,
                   'network_id': network_id,
                   'subnet_id': subnet_id})
        port_obj.IPAllocation.delete_objects(
            context, network_id=network_id, ip_address=ip_address,
            subnet_id=subnet_id)

    @staticmethod
    @db_api.CONTEXT_WRITER
    def _store_ip_allocation(context, ip_address, network_id, subnet_id,
                             port_id):
        LOG.debug("Allocated IP %(ip_address)s "
                  "(%(network_id)s/%(subnet_id)s/%(port_id)s)",
                  {'ip_address': ip_address,
                   'network_id': network_id,
                   'subnet_id': subnet_id,
                   'port_id': port_id})
        allocated = port_obj.IPAllocation(
            context, network_id=network_id, port_id=port_id,
            ip_address=ip_address, subnet_id=subnet_id)
        # NOTE(lujinluo): Add IPAllocations obj to the port fixed_ips
        # in Port OVO integration, i.e. the same way we did in
        # Ib32509d974c8654131112234bcf19d6eae8f7cca
        allocated.create()

    def _make_subnet_dict(self, subnet, fields=None, context=None):
        if isinstance(subnet, subnet_obj.Subnet):
            standard_attr_id = subnet.db_obj.standard_attr.id
        else:
            standard_attr_id = subnet.standard_attr.id

        res = {'id': subnet['id'],
               'name': subnet['name'],
               'tenant_id': subnet['tenant_id'],
               'network_id': subnet['network_id'],
               'ip_version': subnet['ip_version'],
               'subnetpool_id': subnet['subnetpool_id'],
               'enable_dhcp': subnet['enable_dhcp'],
               'ipv6_ra_mode': subnet['ipv6_ra_mode'],
               'ipv6_address_mode': subnet['ipv6_address_mode'],
               'standard_attr_id': standard_attr_id,
               }
        res['gateway_ip'] = str(
                subnet['gateway_ip']) if subnet['gateway_ip'] else None
        # TODO(korzen) this method can get subnet as DB object or Subnet OVO,
        # so temporary workaround will be to fill in the fields in separate
        # ways. After converting all code pieces to use Subnet OVO, the latter
        # 'else' can be deleted
        if isinstance(subnet, subnet_obj.Subnet):
            res['cidr'] = str(subnet.cidr)
            res['allocation_pools'] = [{'start': str(pool.start),
                                       'end': str(pool.end)}
                                       for pool in subnet.allocation_pools]
            res['host_routes'] = [{'destination': str(route.destination),
                                   'nexthop': str(route.nexthop)}
                                  for route in subnet.host_routes]
            res['dns_nameservers'] = [str(dns.address)
                                      for dns in subnet.dns_nameservers]
            res['shared'] = subnet.shared
            # Call auxiliary extend functions, if any
            resource_extend.apply_funcs(subnet_def.COLLECTION_NAME,
                                        res, subnet.db_obj)
        else:
            res['cidr'] = subnet['cidr']
            res['allocation_pools'] = [{'start': pool['first_ip'],
                                       'end': pool['last_ip']}
                                       for pool in subnet['allocation_pools']]
            res['host_routes'] = [{'destination': route['destination'],
                                   'nexthop': route['nexthop']}
                                  for route in subnet['routes']]
            res['dns_nameservers'] = [dns['address']
                                      for dns in subnet['dns_nameservers']]

            # The shared attribute for a subnet is the same
            # as its parent network
            res['shared'] = self._is_network_shared(context,
                                                    subnet.rbac_entries)
            # Call auxiliary extend functions, if any
            resource_extend.apply_funcs(subnet_def.COLLECTION_NAME,
                                        res, subnet)

        return db_utils.resource_fields(res, fields)

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
               'is_default': subnetpool['is_default'],
               'shared': subnetpool['shared'],
               'prefixes': [str(prefix.cidr)
                            for prefix in subnetpool['prefixes']],
               'ip_version': subnetpool['ip_version'],
               'default_quota': subnetpool['default_quota'],
               'address_scope_id': subnetpool['address_scope_id']}
        resource_extend.apply_funcs(
            subnetpool_def.COLLECTION_NAME, res, subnetpool.db_obj)
        return db_utils.resource_fields(res, fields)

    def _make_port_dict(self, port, fields=None,
                        process_extensions=True,
                        with_fixed_ips=True,
                        bulk=False):
        if isinstance(port, port_obj.Port):
            port_data = port.db_obj
            standard_attr_id = port.db_obj.standard_attr.id
        else:
            port_data = port
            standard_attr_id = port.standard_attr.id

        mac = port["mac_address"]
        if isinstance(mac, netaddr.EUI):
            mac.dialect = netaddr.mac_unix_expanded
        res = {"id": port["id"],
               'name': port['name'],
               "network_id": port["network_id"],
               'tenant_id': port['tenant_id'],
               "mac_address": str(mac),
               "admin_state_up": port["admin_state_up"],
               "status": port["status"],
               "device_id": port["device_id"],
               "device_owner": port["device_owner"],
               'standard_attr_id': standard_attr_id,
               }
        if with_fixed_ips:
            res["fixed_ips"] = [
                {'subnet_id': ip["subnet_id"],
                 'ip_address': str(
                     ip["ip_address"])} for ip in port["fixed_ips"]]
        # Call auxiliary extend functions, if any
        if process_extensions:
            res['bulk'] = bulk
            resource_extend.apply_funcs(
                port_def.COLLECTION_NAME, res, port_data)
            res.pop('bulk')
        return db_utils.resource_fields(res, fields)

    def _get_network(self, context, id):
        try:
            network = model_query.get_by_id(context, models_v2.Network, id)
        except exc.NoResultFound:
            raise exceptions.NetworkNotFound(net_id=id)
        return network

    def _network_exists(self, context, network_id):
        query = model_query.query_with_hooks(
            context, models_v2.Network, field='id')
        return query.filter(models_v2.Network.id == network_id).first()

    def _get_subnet_object(self, context, id):
        subnet = subnet_obj.Subnet.get_object(context, id=id)
        if not subnet:
            raise exceptions.SubnetNotFound(subnet_id=id)
        return subnet

    def _get_subnetpool(self, context, id):
        subnetpool = subnetpool_obj.SubnetPool.get_object(
            context, id=id)
        if not subnetpool:
            raise exceptions.SubnetPoolNotFound(subnetpool_id=id)
        return subnetpool

    def _get_port(self, context, id):
        try:
            port = model_query.get_by_id(context, models_v2.Port, id)
        except exc.NoResultFound:
            raise exceptions.PortNotFound(port_id=id)
        return port

    def _get_route_by_subnet(self, context, subnet_id):
        return subnet_obj.Route.get_objects(context,
                                            subnet_id=subnet_id)

    def _get_router_gw_ports_by_network(self, context, network_id):
        return port_obj.Port.get_objects(
            context, network_id=network_id,
            device_owner=constants.DEVICE_OWNER_ROUTER_GW)

    @db_api.CONTEXT_READER
    def _get_subnets_by_network(self, context, network_id):
        return subnet_obj.Subnet.get_objects(context, network_id=network_id)

    @db_api.CONTEXT_READER
    def _get_subnets_by_subnetpool(self, context, subnetpool_id):
        return subnet_obj.Subnet.get_objects(context,
                                             subnetpool_id=subnetpool_id)

    def _get_subnets(self, context, filters=None, sorts=None, limit=None,
                     marker=None, page_reverse=False):
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        filters = filters or {}
        # turn the CIDRs into a proper subnets
        if filters.get('cidr'):
            filters.update(
                {'cidr': [netaddr.IPNetwork(x).cidr for x in filters['cidr']]})
        return subnet_obj.Subnet.get_objects(context, _pager=pager,
                                             validate_filters=False,
                                             **filters)

    def _make_network_dict(self, network, fields=None,
                           process_extensions=True, context=None):
        res = {'id': network['id'],
               'name': network['name'],
               'tenant_id': network['tenant_id'],
               'admin_state_up': network['admin_state_up'],
               'mtu': network.get('mtu', constants.DEFAULT_NETWORK_MTU),
               'status': network['status'],
               'subnets': [subnet['id']
                           for subnet in network['subnets']],
               'standard_attr_id': network.standard_attr.id}
        res['shared'] = self._is_network_shared(context, network.rbac_entries)
        # Call auxiliary extend functions, if any
        if process_extensions:
            resource_extend.apply_funcs(net_def.COLLECTION_NAME, res, network)
        return db_utils.resource_fields(res, fields)

    def _is_network_shared(self, context, rbac_entries):
        # The shared attribute for a network now reflects if the network
        # is shared to the calling tenant via an RBAC entry.
        matches = ('*',) + ((context.tenant_id,) if context else ())
        for entry in rbac_entries:
            if (entry.action == 'access_as_shared' and
                    entry.target_tenant in matches):
                return True
        return False

    def _make_subnet_args(self, detail, subnet, subnetpool_id):
        args = {'project_id': detail.tenant_id,
                'id': detail.subnet_id,
                'name': subnet['name'],
                'network_id': subnet['network_id'],
                'ip_version': subnet['ip_version'],
                'cidr': detail.subnet_cidr,
                'subnetpool_id': subnetpool_id,
                'enable_dhcp': subnet['enable_dhcp'],
                'gateway_ip': detail.gateway_ip,
                'description': subnet.get('description')}
        if subnet['ip_version'] == 6 and subnet['enable_dhcp']:
            if validators.is_attr_set(subnet['ipv6_ra_mode']):
                args['ipv6_ra_mode'] = subnet['ipv6_ra_mode']
            if validators.is_attr_set(subnet['ipv6_address_mode']):
                args['ipv6_address_mode'] = subnet['ipv6_address_mode']
        return args
