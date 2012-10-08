# Copyright (c) 2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import logging
import random

import netaddr
from sqlalchemy import orm
from sqlalchemy.orm import exc

from quantum.api.v2 import attributes
from quantum.common import constants
from quantum.common import exceptions as q_exc
from quantum.common import utils
from quantum.db import api as db
from quantum.db import models_v2
from quantum.openstack.common import cfg
from quantum.openstack.common import timeutils
from quantum import quantum_plugin_base_v2


LOG = logging.getLogger(__name__)

AGENT_OWNER_PREFIX = 'network:'

# Ports with the following 'device_owner' values will not prevent
# network deletion.  If delete_network() finds that all ports on a
# network have these owners, it will explicitly delete each port
# and allow network deletion to continue.  Similarly, if delete_subnet()
# finds out that all existing IP Allocations are associated with ports
# with these owners, it will allow subnet deletion to proceed with the
# IP allocations being cleaned up by cascade.
AUTO_DELETE_PORT_OWNERS = ['network:dhcp', 'network:router_interface']


class QuantumDbPluginV2(quantum_plugin_base_v2.QuantumPluginBaseV2):
    """ A class that implements the v2 Quantum plugin interface
        using SQLAlchemy models.  Whenever a non-read call happens
        the plugin will call an event handler class method (e.g.,
        network_created()).  The result is that this class can be
        sub-classed by other classes that add custom behaviors on
        certain events.
    """

    # This attribute specifies whether the plugin supports or not
    # bulk operations. Name mangling is used in order to ensure it
    # is qualified by class
    __native_bulk_support = True
    # Plugins, mixin classes implementing extension will register
    # hooks into the dict below for "augmenting" the "core way" of
    # building a query for retrieving objects from a model class.
    # To this aim, the register_model_query_hook and unregister_query_hook
    # from this class should be invoked
    _model_query_hooks = {}

    def __init__(self):
        # NOTE(jkoelker) This is an incomlete implementation. Subclasses
        #                must override __init__ and setup the database
        #                and not call into this class's __init__.
        #                This connection is setup as memory for the tests.
        db.configure_db({'sql_connection': "sqlite:///:memory:",
                         'base': models_v2.model_base.BASEV2})

    def _get_tenant_id_for_create(self, context, resource):
        if context.is_admin and 'tenant_id' in resource:
            tenant_id = resource['tenant_id']
        elif ('tenant_id' in resource and
              resource['tenant_id'] != context.tenant_id):
            reason = _('Cannot create resource for another tenant')
            raise q_exc.AdminRequired(reason=reason)
        else:
            tenant_id = context.tenant_id
        return tenant_id

    def _model_query(self, context, model):
        query = context.session.query(model)
        # define basic filter condition for model query
        # NOTE(jkoelker) non-admin queries are scoped to their tenant_id
        # NOTE(salvatore-orlando): unless the model allows for shared objects
        query_filter = None
        if not context.is_admin and hasattr(model, 'tenant_id'):
            if hasattr(model, 'shared'):
                query_filter = ((model.tenant_id == context.tenant_id) |
                                (model.shared))
            else:
                query_filter = (model.tenant_id == context.tenant_id)
        # Execute query hooks registered from mixins and plugins
        for _name, hooks in self._model_query_hooks.get(model,
                                                        {}).iteritems():
            query_hook = hooks.get('query')
            filter_hook = hooks.get('filter')
            if query_hook:
                query = query_hook(self, context, model, query)
            if filter_hook:
                query_filter = filter_hook(self, context, model, query_filter)

        # NOTE(salvatore-orlando): 'if query_filter' will try to evaluate the
        # condition, raising an exception
        if query_filter is not None:
            query = query.filter(query_filter)
        return query

    @classmethod
    def register_model_query_hook(cls, model, name, query_hook, filter_hook):
        """ register an hook to be invoked when a query is executed.

        Add the hooks to the _model_query_hooks dict. Models are the keys
        of this dict, whereas the value is another dict mapping hook names to
        callables performing the hook.
        Each hook has a "query" component, used to build the query expression
        and a "filter" component, which is used to build the filter expression.

        Query hooks take as input the query being built and return a
        transformed query expression.

        Filter hooks take as input the filter expression being built and return
        a transformed filter expression
        """
        model_hooks = cls._model_query_hooks.get(model)
        if not model_hooks:
            # add key to dict
            model_hooks = {}
            cls._model_query_hooks[model] = model_hooks
        model_hooks[name] = {'query': query_hook, 'filter': filter_hook}

    def _get_by_id(self, context, model, id):
        query = self._model_query(context, model)
        return query.filter(model.id == id).one()

    def _get_network(self, context, id):
        try:
            network = self._get_by_id(context, models_v2.Network, id)
        except exc.NoResultFound:
            raise q_exc.NetworkNotFound(net_id=id)
        except exc.MultipleResultsFound:
            LOG.error('Multiple networks match for %s' % id)
            raise q_exc.NetworkNotFound(net_id=id)
        return network

    def _get_subnet(self, context, id):
        try:
            subnet = self._get_by_id(context, models_v2.Subnet, id)
        except exc.NoResultFound:
            raise q_exc.SubnetNotFound(subnet_id=id)
        except exc.MultipleResultsFound:
            LOG.error('Multiple subnets match for %s' % id)
            raise q_exc.SubnetNotFound(subnet_id=id)
        return subnet

    def _get_port(self, context, id):
        try:
            port = self._get_by_id(context, models_v2.Port, id)
        except exc.NoResultFound:
            # NOTE(jkoelker) The PortNotFound exceptions requires net_id
            #                kwarg in order to set the message correctly
            raise q_exc.PortNotFound(port_id=id, net_id=None)
        except exc.MultipleResultsFound:
            LOG.error('Multiple ports match for %s' % id)
            raise q_exc.PortNotFound(port_id=id)
        return port

    def _get_dns_by_subnet(self, context, subnet_id):
        try:
            dns_qry = context.session.query(models_v2.DNSNameServer)
            return dns_qry.filter_by(subnet_id=subnet_id).all()
        except exc.NoResultFound:
            return []

    def _get_route_by_subnet(self, context, subnet_id):
        route_qry = context.session.query(models_v2.Route)
        return route_qry.filter_by(subnet_id=subnet_id).all()

    def _get_subnets_by_network(self, context, network_id):
        subnet_qry = context.session.query(models_v2.Subnet)
        return subnet_qry.filter_by(network_id=network_id).all()

    def _get_all_subnets(self, context):
        # NOTE(salvatore-orlando): This query might end up putting
        # a lot of stress on the db. Consider adding a cache layer
        return context.session.query(models_v2.Subnet).all()

    def _fields(self, resource, fields):
        if fields:
            return dict(((key, item) for key, item in resource.iteritems()
                         if key in fields))
        return resource

    def _apply_filters_to_query(self, query, model, filters):
        if filters:
            for key, value in filters.iteritems():
                column = getattr(model, key, None)
                if column:
                    query = query.filter(column.in_(value))
        return query

    def _get_collection(self, context, model, dict_func, filters=None,
                        fields=None):
        collection = self._model_query(context, model)
        collection = self._apply_filters_to_query(collection, model, filters)
        return [dict_func(c, fields) for c in collection.all()]

    @staticmethod
    def _generate_mac(context, network_id):
        base_mac = cfg.CONF.base_mac.split(':')
        max_retries = cfg.CONF.mac_generation_retries
        for i in range(max_retries):
            mac = [int(base_mac[0], 16), int(base_mac[1], 16),
                   int(base_mac[2], 16), random.randint(0x00, 0xff),
                   random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
            if base_mac[3] != '00':
                mac[3] = int(base_mac[3], 16)
            mac_address = ':'.join(map(lambda x: "%02x" % x, mac))
            if QuantumDbPluginV2._check_unique_mac(context, network_id,
                                                   mac_address):
                LOG.debug("Generated mac for network %s is %s",
                          network_id, mac_address)
                return mac_address
            else:
                LOG.debug("Generated mac %s exists. Remaining attempts %s.",
                          mac_address, max_retries - (i + 1))
        LOG.error("Unable to generate mac address after %s attempts",
                  max_retries)
        raise q_exc.MacAddressGenerationFailure(net_id=network_id)

    @staticmethod
    def _check_unique_mac(context, network_id, mac_address):
        mac_qry = context.session.query(models_v2.Port)
        try:
            mac_qry.filter_by(network_id=network_id,
                              mac_address=mac_address).one()
        except exc.NoResultFound:
            return True
        return False

    @staticmethod
    def _hold_ip(context, network_id, subnet_id, port_id, ip_address):
        alloc_qry = context.session.query(models_v2.IPAllocation)
        allocated = alloc_qry.filter_by(network_id=network_id,
                                        port_id=port_id,
                                        ip_address=ip_address,
                                        subnet_id=subnet_id).one()

        if not allocated:
            return
        if allocated.expiration < timeutils.utcnow():
            # immediately delete expired allocations
            QuantumDbPluginV2._recycle_ip(
                context, network_id, subnet_id, ip_address)
        else:
            LOG.debug("Hold allocated IP %s (%s/%s/%s)", ip_address,
                      network_id, subnet_id, port_id)
            allocated.port_id = None

    @staticmethod
    def _recycle_expired_ip_allocations(context, network_id):
        """Return held ip allocations with expired leases back to the pool."""
        if network_id in getattr(context, '_recycled_networks', set()):
            return

        expired_qry = context.session.query(models_v2.IPAllocation)
        expired_qry = expired_qry.filter_by(network_id=network_id,
                                            port_id=None)
        expired_qry = expired_qry.filter(
            models_v2.IPAllocation.expiration <= timeutils.utcnow())

        for expired in expired_qry.all():
            QuantumDbPluginV2._recycle_ip(context,
                                          network_id,
                                          expired['subnet_id'],
                                          expired['ip_address'])

        if hasattr(context, '_recycled_networks'):
            context._recycled_networks.add(network_id)
        else:
            context._recycled_networks = set([network_id])

    @staticmethod
    def _recycle_ip(context, network_id, subnet_id, ip_address):
        """Return an IP address to the pool of free IP's on the network
        subnet.
        """
        # Grab all allocation pools for the subnet
        pool_qry = context.session.query(models_v2.IPAllocationPool)
        allocation_pools = pool_qry.filter_by(subnet_id=subnet_id).all()
        # Find the allocation pool for the IP to recycle
        pool_id = None
        for allocation_pool in allocation_pools:
            allocation_pool_range = netaddr.IPRange(
                allocation_pool['first_ip'],
                allocation_pool['last_ip'])
            if netaddr.IPAddress(ip_address) in allocation_pool_range:
                pool_id = allocation_pool['id']
                break
        if not pool_id:
            error_message = _("No allocation pool found for "
                              "ip address:%s" % ip_address)
            raise q_exc.InvalidInput(error_message=error_message)
        # Two requests will be done on the database. The first will be to
        # search if an entry starts with ip_address + 1 (r1). The second
        # will be to see if an entry ends with ip_address -1 (r2).
        # If 1 of the above holds true then the specific entry will be
        # modified. If both hold true then the two ranges will be merged.
        # If there are no entries then a single entry will be added.
        range_qry = context.session.query(models_v2.IPAvailabilityRange)
        ip_first = str(netaddr.IPAddress(ip_address) + 1)
        ip_last = str(netaddr.IPAddress(ip_address) - 1)
        LOG.debug("Recycle %s", ip_address)
        try:
            r1 = range_qry.filter_by(allocation_pool_id=pool_id,
                                     first_ip=ip_first).one()
            LOG.debug("Recycle: first match for %s-%s", r1['first_ip'],
                      r1['last_ip'])
        except exc.NoResultFound:
            r1 = []
        try:
            r2 = range_qry.filter_by(allocation_pool_id=pool_id,
                                     last_ip=ip_last).one()
            LOG.debug("Recycle: last match for %s-%s", r2['first_ip'],
                      r2['last_ip'])
        except exc.NoResultFound:
            r2 = []

        if r1 and r2:
            # Merge the two ranges
            ip_range = models_v2.IPAvailabilityRange(
                allocation_pool_id=pool_id,
                first_ip=r2['first_ip'],
                last_ip=r1['last_ip'])
            context.session.add(ip_range)
            LOG.debug("Recycle: merged %s-%s and %s-%s", r2['first_ip'],
                      r2['last_ip'], r1['first_ip'], r1['last_ip'])
            context.session.delete(r1)
            context.session.delete(r2)
        elif r1:
            # Update the range with matched first IP
            r1['first_ip'] = ip_address
            LOG.debug("Recycle: updated first %s-%s", r1['first_ip'],
                      r1['last_ip'])
        elif r2:
            # Update the range with matched last IP
            r2['last_ip'] = ip_address
            LOG.debug("Recycle: updated last %s-%s", r2['first_ip'],
                      r2['last_ip'])
        else:
            # Create a new range
            ip_range = models_v2.IPAvailabilityRange(
                allocation_pool_id=pool_id,
                first_ip=ip_address,
                last_ip=ip_address)
            context.session.add(ip_range)
            LOG.debug("Recycle: created new %s-%s", ip_address, ip_address)
        QuantumDbPluginV2._delete_ip_allocation(context, network_id, subnet_id,
                                                ip_address)

    @staticmethod
    def _default_allocation_expiration():
        return (timeutils.utcnow() +
                datetime.timedelta(seconds=cfg.CONF.dhcp_lease_duration))

    def update_fixed_ip_lease_expiration(self, context, network_id,
                                         ip_address, lease_remaining):

        expiration = timeutils.utcnow() + datetime.timedelta(lease_remaining)

        query = context.session.query(models_v2.IPAllocation)
        query = query.filter_by(network_id=network_id, ip_address=ip_address)

        try:
            fixed_ip = query.one()
            fixed_ip.expiration = expiration
        except exc.NoResultFound:
            LOG.debug("No fixed IP found that matches the network %s and "
                      "ip address %s.", network_id, ip_address)

    @staticmethod
    def _delete_ip_allocation(context, network_id, subnet_id, ip_address):

        # Delete the IP address from the IPAllocate table
        LOG.debug("Delete allocated IP %s (%s/%s)", ip_address,
                  network_id, subnet_id)
        alloc_qry = context.session.query(models_v2.IPAllocation)
        allocated = alloc_qry.filter_by(network_id=network_id,
                                        ip_address=ip_address,
                                        subnet_id=subnet_id).delete()

    @staticmethod
    def _generate_ip(context, network_id, subnets):
        """Generate an IP address.

        The IP address will be generated from one of the subnets defined on
        the network.
        """
        range_qry = context.session.query(
            models_v2.IPAvailabilityRange).join(
                models_v2.IPAllocationPool)
        for subnet in subnets:
            range = range_qry.filter_by(subnet_id=subnet['id']).first()
            if not range:
                LOG.debug("All IP's from subnet %s (%s) allocated",
                          subnet['id'], subnet['cidr'])
                continue
            ip_address = range['first_ip']
            LOG.debug("Allocated IP - %s from %s to %s", ip_address,
                      range['first_ip'], range['last_ip'])
            if range['first_ip'] == range['last_ip']:
                # No more free indices on subnet => delete
                LOG.debug("No more free IP's in slice. Deleting allocation "
                          "pool.")
                context.session.delete(range)
            else:
                # increment the first free
                range['first_ip'] = str(netaddr.IPAddress(ip_address) + 1)
            return {'ip_address': ip_address, 'subnet_id': subnet['id']}
        raise q_exc.IpAddressGenerationFailure(net_id=network_id)

    @staticmethod
    def _allocate_specific_ip(context, subnet_id, ip_address):
        """Allocate a specific IP address on the subnet."""
        ip = int(netaddr.IPAddress(ip_address))
        range_qry = context.session.query(
            models_v2.IPAvailabilityRange,
            models_v2.IPAllocationPool).join(
                models_v2.IPAllocationPool)
        results = range_qry.filter_by(subnet_id=subnet_id).all()
        for (range, pool) in results:
            first = int(netaddr.IPAddress(range['first_ip']))
            last = int(netaddr.IPAddress(range['last_ip']))
            if first <= ip <= last:
                if first == last:
                    context.session.delete(range)
                    return
                elif first == ip:
                    range['first_ip'] = str(netaddr.IPAddress(ip_address) + 1)
                    return
                elif last == ip:
                    range['last_ip'] = str(netaddr.IPAddress(ip_address) - 1)
                    return
                else:
                    # Split into two ranges
                    new_first = str(netaddr.IPAddress(ip_address) + 1)
                    new_last = range['last_ip']
                    range['last_ip'] = str(netaddr.IPAddress(ip_address) - 1)
                    ip_range = models_v2.IPAvailabilityRange(
                        allocation_pool_id=pool['id'],
                        first_ip=new_first,
                        last_ip=new_last)
                    context.session.add(ip_range)
                    return

    @staticmethod
    def _check_unique_ip(context, network_id, subnet_id, ip_address):
        """Validate that the IP address on the subnet is not in use."""
        ip_qry = context.session.query(models_v2.IPAllocation)
        try:
            ip_qry.filter_by(network_id=network_id,
                             subnet_id=subnet_id,
                             ip_address=ip_address).one()
        except exc.NoResultFound:
            return True
        return False

    @staticmethod
    def _check_subnet_ip(cidr, ip_address):
        """Validate that the IP address is on the subnet."""
        ip = netaddr.IPAddress(ip_address)
        net = netaddr.IPNetwork(cidr)
        # Check that the IP is valid on subnet. This cannot be the
        # network or the broadcast address
        if (ip != net.network and
                ip != net.broadcast and
                net.netmask & ip == net.ip):
            return True
        return False

    def _test_fixed_ips_for_port(self, context, network_id, fixed_ips):
        """Test fixed IPs for port.

        Check that configured subnets are valid prior to allocating any
        IPs. Include the subnet_id in the result if only an IP address is
        configured.

        :raises: InvalidInput, IpAddressInUse
        """
        fixed_ip_set = []
        for fixed in fixed_ips:
            found = False
            if 'subnet_id' not in fixed:
                if 'ip_address' not in fixed:
                    msg = _('IP allocation requires subnet_id or ip_address')
                    raise q_exc.InvalidInput(error_message=msg)

                filter = {'network_id': [network_id]}
                subnets = self.get_subnets(context, filters=filter)
                for subnet in subnets:
                    if QuantumDbPluginV2._check_subnet_ip(subnet['cidr'],
                                                          fixed['ip_address']):
                        found = True
                        subnet_id = subnet['id']
                        break
                if not found:
                    msg = _('IP address %s is not a valid IP for the defined '
                            'networks subnets') % fixed['ip_address']
                    raise q_exc.InvalidInput(error_message=msg)
            else:
                subnet = self._get_subnet(context, fixed['subnet_id'])
                if subnet['network_id'] != network_id:
                    msg = _('Failed to create port on network %s, '
                            'because fixed_ips included invalid subnet '
                            '%s') % (network_id, fixed['subnet_id'])
                    raise q_exc.InvalidInput(error_message=msg)
                subnet_id = subnet['id']

            if 'ip_address' in fixed:
                # Ensure that the IP's are unique
                if not QuantumDbPluginV2._check_unique_ip(context, network_id,
                                                          subnet_id,
                                                          fixed['ip_address']):
                    raise q_exc.IpAddressInUse(net_id=network_id,
                                               ip_address=fixed['ip_address'])

                # Ensure that the IP is valid on the subnet
                if (not found and
                    not QuantumDbPluginV2._check_subnet_ip(
                        subnet['cidr'], fixed['ip_address'])):
                    msg = _('IP address %s is not a valid IP for the defined '
                            'subnet') % fixed['ip_address']
                    raise q_exc.InvalidInput(error_message=msg)

                fixed_ip_set.append({'subnet_id': subnet_id,
                                     'ip_address': fixed['ip_address']})
            else:
                fixed_ip_set.append({'subnet_id': subnet_id})
        return fixed_ip_set

    def _allocate_fixed_ips(self, context, network, fixed_ips):
        """Allocate IP addresses according to the configured fixed_ips."""
        ips = []
        for fixed in fixed_ips:
            if 'ip_address' in fixed:
                # Remove the IP address from the allocation pool
                QuantumDbPluginV2._allocate_specific_ip(
                    context, fixed['subnet_id'], fixed['ip_address'])
                ips.append({'ip_address': fixed['ip_address'],
                            'subnet_id': fixed['subnet_id']})
            # Only subnet ID is specified => need to generate IP
            # from subnet
            else:
                subnets = [self._get_subnet(context, fixed['subnet_id'])]
                # IP address allocation
                result = self._generate_ip(context, network, subnets)
                ips.append({'ip_address': result['ip_address'],
                            'subnet_id': result['subnet_id']})
        return ips

    def _update_ips_for_port(self, context, network_id, port_id, original_ips,
                             new_ips):
        """Add or remove IPs from the port."""
        ips = []

        # Remove all of the intersecting elements
        for original_ip in original_ips[:]:
            for new_ip in new_ips[:]:
                if 'ip_address' in new_ip:
                    if (original_ip['ip_address'] == new_ip['ip_address']
                            and
                            original_ip['subnet_id'] == new_ip['subnet_id']):
                        original_ips.remove(original_ip)
                        new_ips.remove(new_ip)

        # Check if the IP's to add are OK
        to_add = self._test_fixed_ips_for_port(context, network_id, new_ips)
        for ip in original_ips:
            LOG.debug("Port update. Hold %s", ip)
            QuantumDbPluginV2._hold_ip(context,
                                       network_id,
                                       ip['subnet_id'],
                                       port_id,
                                       ip['ip_address'])

        if to_add:
            LOG.debug("Port update. Adding %s", to_add)
            network = self._get_network(context, network_id)
            ips = self._allocate_fixed_ips(context, network, to_add)
        return ips

    def _allocate_ips_for_port(self, context, network, port):
        """Allocate IP addresses for the port.

        If port['fixed_ips'] is set to 'ATTR_NOT_SPECIFIED', allocate IP
        addresses for the port. If port['fixed_ips'] contains an IP address or
        a subnet_id then allocate an IP address accordingly.
        """
        p = port['port']
        ips = []

        fixed_configured = (p['fixed_ips'] != attributes.ATTR_NOT_SPECIFIED)
        if fixed_configured:
            configured_ips = self._test_fixed_ips_for_port(context,
                                                           p["network_id"],
                                                           p['fixed_ips'])
            ips = self._allocate_fixed_ips(context, network, configured_ips)
        else:
            filter = {'network_id': [p['network_id']]}
            subnets = self.get_subnets(context, filters=filter)
            # Split into v4 and v6 subnets
            v4 = []
            v6 = []
            for subnet in subnets:
                if subnet['ip_version'] == 4:
                    v4.append(subnet)
                else:
                    v6.append(subnet)
            version_subnets = [v4, v6]
            for subnets in version_subnets:
                if subnets:
                    result = QuantumDbPluginV2._generate_ip(context, network,
                                                            subnets)
                    ips.append({'ip_address': result['ip_address'],
                                'subnet_id': result['subnet_id']})
        return ips

    def _validate_subnet_cidr(self, context, network, new_subnet_cidr):
        """Validate the CIDR for a subnet.

        Verifies the specified CIDR does not overlap with the ones defined
        for the other subnets specified for this network, or with any other
        CIDR if overlapping IPs are disabled.

        """
        new_subnet_ipset = netaddr.IPSet([new_subnet_cidr])
        subnet_list = network.subnets
        if not cfg.CONF.allow_overlapping_ips:
            subnet_list = self._get_all_subnets(context)
        for subnet in subnet_list:
            if (netaddr.IPSet([subnet.cidr]) & new_subnet_ipset):
                # don't give out details of the overlapping subnet
                err_msg = _("Requested subnet with cidr: %s "
                            "for network: %s overlaps with another subnet" %
                            (new_subnet_cidr, network.id))
                LOG.error("Validation for CIDR:%s failed - overlaps with "
                          "subnet %s (CIDR:%s)",
                          new_subnet_cidr, subnet.id, subnet.cidr)
                raise q_exc.InvalidInput(error_message=err_msg)

    def _validate_allocation_pools(self, ip_pools, gateway_ip, subnet_cidr):
        """Validate IP allocation pools.

        Verify start and end address for each allocation pool are valid,
        ie: constituted by valid and appropriately ordered IP addresses.
        Also, verify pools do not overlap among themselves and with the
        gateway IP. Finally, verify that each range, and the gateway IP,
        fall within the subnet's CIDR.

        """

        subnet = netaddr.IPNetwork(subnet_cidr)
        subnet_first_ip = netaddr.IPAddress(subnet.first + 1)
        subnet_last_ip = netaddr.IPAddress(subnet.last - 1)

        LOG.debug("Performing IP validity checks on allocation pools")
        ip_sets = []
        for ip_pool in ip_pools:
            try:
                start_ip = netaddr.IPAddress(ip_pool['start'])
                end_ip = netaddr.IPAddress(ip_pool['end'])
            except netaddr.AddrFormatError:
                LOG.error("Found invalid IP address in pool: %s - %s:",
                          ip_pool['start'],
                          ip_pool['end'])
                raise q_exc.InvalidAllocationPool(pool=ip_pool)
            if (start_ip.version != subnet.version or
                    end_ip.version != subnet.version):
                LOG.error("Specified IP addresses do not match "
                          "the subnet IP version")
                raise q_exc.InvalidAllocationPool(pool=ip_pool)
            if end_ip < start_ip:
                LOG.error("Start IP (%s) is greater than end IP (%s)",
                          ip_pool['start'],
                          ip_pool['end'])
                raise q_exc.InvalidAllocationPool(pool=ip_pool)
            if start_ip < subnet_first_ip or end_ip > subnet_last_ip:
                LOG.error("Found pool larger than subnet CIDR:%s - %s",
                          ip_pool['start'],
                          ip_pool['end'])
                raise q_exc.OutOfBoundsAllocationPool(
                    pool=ip_pool,
                    subnet_cidr=subnet_cidr)
            # Valid allocation pool
            # Create an IPSet for it for easily verifying overlaps
            ip_sets.append(netaddr.IPSet(netaddr.IPRange(
                ip_pool['start'],
                ip_pool['end']).cidrs()))

        LOG.debug("Checking for overlaps among allocation pools "
                  "and gateway ip")
        ip_ranges = ip_pools[:]
        # Treat gw as IPset as well
        if gateway_ip:
            ip_ranges.append(gateway_ip)
            ip_sets.append(netaddr.IPSet([gateway_ip]))
        # Use integer cursors as an efficient way for implementing
        # comparison and avoiding comparing the same pair twice
        for l_cursor in range(len(ip_sets)):
            for r_cursor in range(l_cursor + 1, len(ip_sets)):
                if ip_sets[l_cursor] & ip_sets[r_cursor]:
                    l_range = ip_ranges[l_cursor]
                    r_range = ip_ranges[r_cursor]
                    LOG.error("Found overlapping ranges: %s and %s",
                              l_range, r_range)
                    raise q_exc.OverlappingAllocationPools(
                        pool_1=l_range,
                        pool_2=r_range,
                        subnet_cidr=subnet_cidr)

    def _validate_host_route(self, route, ip_version):
        try:
            netaddr.IPNetwork(route['destination'])
            netaddr.IPAddress(route['nexthop'])
        except netaddr.core.AddrFormatError:
            err_msg = ("invalid route: %s" % (str(route)))
            raise q_exc.InvalidInput(error_message=err_msg)
        except ValueError:
            # netaddr.IPAddress would raise this
            err_msg = _("invalid route: %s") % str(route)
            raise q_exc.InvalidInput(error_message=err_msg)
        self._validate_ip_version(ip_version, route['nexthop'], 'nexthop')
        self._validate_ip_version(ip_version, route['destination'],
                                  'destination')

    def _allocate_pools_for_subnet(self, context, subnet):
        """Create IP allocation pools for a given subnet

        Pools are defined by the 'allocation_pools' attribute,
        a list of dict objects with 'start' and 'end' keys for
        defining the pool range.

        """

        pools = []
        if subnet['allocation_pools'] == attributes.ATTR_NOT_SPECIFIED:
            # Auto allocate the pool around gateway_ip
            net = netaddr.IPNetwork(subnet['cidr'])
            first_ip = net.first + 1
            last_ip = net.last - 1
            gw_ip = int(netaddr.IPAddress(subnet['gateway_ip'] or net.last))
            # Use the gw_ip to find a point for splitting allocation pools
            # for this subnet
            split_ip = min(max(gw_ip, net.first), net.last)
            if split_ip > first_ip:
                pools.append({'start': str(netaddr.IPAddress(first_ip)),
                              'end': str(netaddr.IPAddress(split_ip - 1))})
            if split_ip < last_ip:
                pools.append({'start': str(netaddr.IPAddress(split_ip + 1)),
                              'end': str(netaddr.IPAddress(last_ip))})
            # return auto-generated pools
            # no need to check for their validity
            return pools
        else:
            pools = subnet['allocation_pools']
            self._validate_allocation_pools(pools,
                                            subnet['gateway_ip'],
                                            subnet['cidr'])
            return pools

    def _validate_shared_update(self, context, id, original, updated):
        # The only case that needs to be validated is when 'shared'
        # goes from True to False
        if updated['shared'] == original.shared or updated['shared']:
            return
        ports = self._model_query(
            context, models_v2.Port).filter(
                models_v2.Port.network_id == id).all()
        subnets = self._model_query(
            context, models_v2.Subnet).filter(
                models_v2.Subnet.network_id == id).all()
        tenant_ids = set([port['tenant_id'] for port in ports] +
                         [subnet['tenant_id'] for subnet in subnets])
        # raise if multiple tenants found or if the only tenant found
        # is not the owner of the network
        if (len(tenant_ids) > 1 or len(tenant_ids) == 1 and
            tenant_ids.pop() != original.tenant_id):
            raise q_exc.InvalidSharedSetting(network=original.name)

    def _make_network_dict(self, network, fields=None):
        res = {'id': network['id'],
               'name': network['name'],
               'tenant_id': network['tenant_id'],
               'admin_state_up': network['admin_state_up'],
               'status': network['status'],
               'shared': network['shared'],
               'subnets': [subnet['id']
                           for subnet in network['subnets']]}

        return self._fields(res, fields)

    def _make_subnet_dict(self, subnet, fields=None):
        res = {'id': subnet['id'],
               'name': subnet['name'],
               'tenant_id': subnet['tenant_id'],
               'network_id': subnet['network_id'],
               'ip_version': subnet['ip_version'],
               'cidr': subnet['cidr'],
               'allocation_pools': [{'start': pool['first_ip'],
                                     'end': pool['last_ip']}
                                    for pool in subnet['allocation_pools']],
               'gateway_ip': subnet['gateway_ip'],
               'enable_dhcp': subnet['enable_dhcp'],
               'dns_nameservers': [dns['address']
                                   for dns in subnet['dns_nameservers']],
               'host_routes': [{'destination': route['destination'],
                                'nexthop': route['nexthop']}
                               for route in subnet['routes']],
               'shared': subnet['shared']
               }
        if subnet['gateway_ip']:
            res['gateway_ip'] = subnet['gateway_ip']

        return self._fields(res, fields)

    def _make_port_dict(self, port, fields=None):
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
        return self._fields(res, fields)

    def _create_bulk(self, resource, context, request_items):
        objects = []
        collection = "%ss" % resource
        items = request_items[collection]
        context.session.begin(subtransactions=True)
        try:
            for item in items:
                obj_creator = getattr(self, 'create_%s' % resource)
                objects.append(obj_creator(context, item))
            context.session.commit()
        except Exception:
            LOG.exception("An exception occured while creating "
                          "the %s:%s", resource, item)
            context.session.rollback()
            raise
        return objects

    def create_network_bulk(self, context, networks):
        return self._create_bulk('network', context, networks)

    def create_network(self, context, network):
        """ handle creation of a single network """
        # single request processing
        n = network['network']
        # NOTE(jkoelker) Get the tenant_id outside of the session to avoid
        #                unneeded db action if the operation raises
        tenant_id = self._get_tenant_id_for_create(context, n)
        with context.session.begin(subtransactions=True):
            network = models_v2.Network(tenant_id=tenant_id,
                                        id=n.get('id') or utils.str_uuid(),
                                        name=n['name'],
                                        admin_state_up=n['admin_state_up'],
                                        shared=n['shared'],
                                        status=constants.NET_STATUS_ACTIVE)
            context.session.add(network)
        return self._make_network_dict(network)

    def update_network(self, context, id, network):
        n = network['network']
        with context.session.begin(subtransactions=True):
            network = self._get_network(context, id)
            # validate 'shared' parameter
            if 'shared' in n:
                self._validate_shared_update(context, id, network, n)
            network.update(n)
            # also update shared in all the subnets for this network
            subnets = self._get_subnets_by_network(context, id)
            for subnet in subnets:
                subnet['shared'] = network['shared']
        return self._make_network_dict(network)

    def delete_network(self, context, id):
        with context.session.begin(subtransactions=True):
            network = self._get_network(context, id)

            filter = {'network_id': [id]}
            ports = self.get_ports(context, filters=filter)

            # check if there are any tenant owned ports in-use
            only_auto_del = all(p['device_owner'] in AUTO_DELETE_PORT_OWNERS
                                for p in ports)

            if not only_auto_del:
                raise q_exc.NetworkInUse(net_id=id)

            # clean up network owned ports
            for port in ports:
                self._delete_port(context, port['id'])

            # clean up subnets
            subnets_qry = context.session.query(models_v2.Subnet)
            subnets_qry.filter_by(network_id=id).delete()
            context.session.delete(network)

    def get_network(self, context, id, fields=None):
        network = self._get_network(context, id)
        return self._make_network_dict(network, fields)

    def get_networks(self, context, filters=None, fields=None):
        return self._get_collection(context, models_v2.Network,
                                    self._make_network_dict,
                                    filters=filters, fields=fields)

    def create_subnet_bulk(self, context, subnets):
        return self._create_bulk('subnet', context, subnets)

    def _validate_ip_version(self, ip_version, addr, name):
        """Check IP field of a subnet match specified ip version"""
        ip = netaddr.IPNetwork(addr)
        if ip.version != ip_version:
            msg = _("%(name)s '%(addr)s' does not match "
                    "the ip_version '%(ip_version)s'") % locals()
            raise q_exc.InvalidInput(error_message=msg)

    def _validate_subnet(self, s):
        """Validate a subnet spec"""

        # The method requires the subnet spec 's' has 'ip_version' field.
        # If 's' dict does not have 'ip_version' field in an API call
        # (e.g., update_subnet()), you need to set 'ip_version' field
        # before calling this method.
        ip_ver = s['ip_version']

        if 'cidr' in s:
            self._validate_ip_version(ip_ver, s['cidr'], 'cidr')
        if ('gateway_ip' in s and
            s['gateway_ip'] and
            s['gateway_ip'] != attributes.ATTR_NOT_SPECIFIED):
            self._validate_ip_version(ip_ver, s['gateway_ip'], 'gateway_ip')

        if 'dns_nameservers' in s and \
                s['dns_nameservers'] != attributes.ATTR_NOT_SPECIFIED:
            if len(s['dns_nameservers']) > cfg.CONF.max_dns_nameservers:
                raise q_exc.DNSNameServersExhausted(
                    subnet_id=id,
                    quota=cfg.CONF.max_dns_nameservers)
            for dns in s['dns_nameservers']:
                try:
                    netaddr.IPAddress(dns)
                except Exception:
                    raise q_exc.InvalidInput(
                        error_message=("error parsing dns address %s" % dns))
                self._validate_ip_version(ip_ver, dns, 'dns_nameserver')

        if 'host_routes' in s and \
                s['host_routes'] != attributes.ATTR_NOT_SPECIFIED:
            if len(s['host_routes']) > cfg.CONF.max_subnet_host_routes:
                raise q_exc.HostRoutesExhausted(
                    subnet_id=id,
                    quota=cfg.CONF.max_subnet_host_routes)
            # check if the routes are all valid
            for rt in s['host_routes']:
                self._validate_host_route(rt, ip_ver)

    def create_subnet(self, context, subnet):
        s = subnet['subnet']
        self._validate_subnet(s)

        net = netaddr.IPNetwork(s['cidr'])
        if s['gateway_ip'] == attributes.ATTR_NOT_SPECIFIED:
            s['gateway_ip'] = str(netaddr.IPAddress(net.first + 1))

        tenant_id = self._get_tenant_id_for_create(context, s)
        with context.session.begin(subtransactions=True):
            network = self._get_network(context, s["network_id"])
            self._validate_subnet_cidr(context, network, s['cidr'])
            # The 'shared' attribute for subnets is for internal plugin
            # use only. It is not exposed through the API
            subnet = models_v2.Subnet(tenant_id=tenant_id,
                                      id=s.get('id') or utils.str_uuid(),
                                      name=s['name'],
                                      network_id=s['network_id'],
                                      ip_version=s['ip_version'],
                                      cidr=s['cidr'],
                                      enable_dhcp=s['enable_dhcp'],
                                      gateway_ip=s['gateway_ip'],
                                      shared=network.shared)

            # perform allocate pools first, since it might raise an error
            pools = self._allocate_pools_for_subnet(context, s)

            context.session.add(subnet)
            if s['dns_nameservers'] != attributes.ATTR_NOT_SPECIFIED:
                for addr in s['dns_nameservers']:
                    ns = models_v2.DNSNameServer(address=addr,
                                                 subnet_id=subnet.id)
                    context.session.add(ns)

            if s['host_routes'] != attributes.ATTR_NOT_SPECIFIED:
                for rt in s['host_routes']:
                    route = models_v2.Route(subnet_id=subnet.id,
                                            destination=rt['destination'],
                                            nexthop=rt['nexthop'])
                    context.session.add(route)
            for pool in pools:
                ip_pool = models_v2.IPAllocationPool(subnet=subnet,
                                                     first_ip=pool['start'],
                                                     last_ip=pool['end'])
                context.session.add(ip_pool)
                ip_range = models_v2.IPAvailabilityRange(
                    ipallocationpool=ip_pool,
                    first_ip=pool['start'],
                    last_ip=pool['end'])
                context.session.add(ip_range)

        return self._make_subnet_dict(subnet)

    def update_subnet(self, context, id, subnet):
        """Update the subnet with new info. The change however will not be
           realized until the client renew the dns lease or we support
           gratuitous DHCP offers"""

        s = subnet['subnet']
        # Fill 'ip_version' field with the current value since
        # _validate_subnet() expects subnet spec has 'ip_version' field.
        s['ip_version'] = self._get_subnet(context, id).ip_version
        self._validate_subnet(s)

        with context.session.begin(subtransactions=True):
            if "dns_nameservers" in s:
                old_dns_list = self._get_dns_by_subnet(context, id)

                new_dns_addr_set = set(s["dns_nameservers"])
                old_dns_addr_set = set([dns['address']
                                        for dns in old_dns_list])

                for dns_addr in old_dns_addr_set - new_dns_addr_set:
                    for dns in old_dns_list:
                        if dns['address'] == dns_addr:
                            context.session.delete(dns)
                for dns_addr in new_dns_addr_set - old_dns_addr_set:
                    dns = models_v2.DNSNameServer(
                        address=dns_addr,
                        subnet_id=id)
                    context.session.add(dns)
                del s["dns_nameservers"]

            def _combine(ht):
                return ht['destination'] + "_" + ht['nexthop']

            if "host_routes" in s:
                old_route_list = self._get_route_by_subnet(context, id)

                new_route_set = set([_combine(route)
                                     for route in s['host_routes']])

                old_route_set = set([_combine(route)
                                     for route in old_route_list])

                for route_str in old_route_set - new_route_set:
                    for route in old_route_list:
                        if _combine(route) == route_str:
                            context.session.delete(route)
                for route_str in new_route_set - old_route_set:
                    route = models_v2.Route(
                        destination=route_str.partition("_")[0],
                        nexthop=route_str.partition("_")[2],
                        subnet_id=id)
                    context.session.add(route)
                del s["host_routes"]

            subnet = self._get_subnet(context, id)
            subnet.update(s)
        return self._make_subnet_dict(subnet)

    def delete_subnet(self, context, id):
        with context.session.begin(subtransactions=True):
            subnet = self._get_subnet(context, id)
            # Check if any tenant owned ports are using this subnet
            allocated_qry = context.session.query(models_v2.IPAllocation)
            allocated_qry = allocated_qry.options(orm.joinedload('ports'))
            allocated = allocated_qry.filter_by(subnet_id=id).all()

            only_auto_del = all(not a.port_id or
                                a.ports.device_owner in AUTO_DELETE_PORT_OWNERS
                                for a in allocated)
            if not only_auto_del:
                raise q_exc.NetworkInUse(subnet_id=id)

            # remove network owned ports
            for allocation in allocated:
                context.session.delete(allocation)

            context.session.delete(subnet)

    def get_subnet(self, context, id, fields=None):
        subnet = self._get_subnet(context, id)
        return self._make_subnet_dict(subnet, fields)

    def get_subnets(self, context, filters=None, fields=None):
        return self._get_collection(context, models_v2.Subnet,
                                    self._make_subnet_dict,
                                    filters=filters, fields=fields)

    def create_port_bulk(self, context, ports):
        return self._create_bulk('port', context, ports)

    def create_port(self, context, port):
        p = port['port']
        # NOTE(jkoelker) Get the tenant_id outside of the session to avoid
        #                unneeded db action if the operation raises
        tenant_id = self._get_tenant_id_for_create(context, p)

        with context.session.begin(subtransactions=True):
            self._recycle_expired_ip_allocations(context, p['network_id'])
            network = self._get_network(context, p["network_id"])

            # Ensure that a MAC address is defined and it is unique on the
            # network
            if p['mac_address'] == attributes.ATTR_NOT_SPECIFIED:
                p['mac_address'] = QuantumDbPluginV2._generate_mac(
                    context, p["network_id"])
            else:
                # Ensure that the mac on the network is unique
                if not QuantumDbPluginV2._check_unique_mac(context,
                                                           p["network_id"],
                                                           p['mac_address']):
                    raise q_exc.MacAddressInUse(net_id=p["network_id"],
                                                mac=p['mac_address'])

            # Returns the IP's for the port
            ips = self._allocate_ips_for_port(context, network, port)

            port = models_v2.Port(tenant_id=tenant_id,
                                  name=p['name'],
                                  id=p.get('id') or utils.str_uuid(),
                                  network_id=p['network_id'],
                                  mac_address=p['mac_address'],
                                  admin_state_up=p['admin_state_up'],
                                  status=constants.PORT_STATUS_ACTIVE,
                                  device_id=p['device_id'],
                                  device_owner=p['device_owner'])
            context.session.add(port)

            # Update the allocated IP's
            if ips:
                for ip in ips:
                    LOG.debug("Allocated IP %s (%s/%s/%s)", ip['ip_address'],
                              port['network_id'], ip['subnet_id'], port.id)
                    allocated = models_v2.IPAllocation(
                        network_id=port['network_id'],
                        port_id=port.id,
                        ip_address=ip['ip_address'],
                        subnet_id=ip['subnet_id'],
                        expiration=self._default_allocation_expiration()
                    )
                    context.session.add(allocated)

        return self._make_port_dict(port)

    def update_port(self, context, id, port):
        p = port['port']

        with context.session.begin(subtransactions=True):
            port = self._get_port(context, id)
            # Check if the IPs need to be updated
            if 'fixed_ips' in p:
                self._recycle_expired_ip_allocations(context,
                                                     port['network_id'])
                original = self._make_port_dict(port)
                ips = self._update_ips_for_port(context,
                                                port["network_id"],
                                                id,
                                                original["fixed_ips"],
                                                p['fixed_ips'])
                # 'fixed_ip's not part of DB so it is deleted
                del p['fixed_ips']

                # Update ips if necessary
                for ip in ips:
                    allocated = models_v2.IPAllocation(
                        network_id=port['network_id'], port_id=port.id,
                        ip_address=ip['ip_address'], subnet_id=ip['subnet_id'],
                        expiration=self._default_allocation_expiration())
                    context.session.add(allocated)

            port.update(p)

        return self._make_port_dict(port)

    def delete_port(self, context, id):
        with context.session.begin(subtransactions=True):
            self._delete_port(context, id)

    def _delete_port(self, context, id):
        port = self._get_port(context, id)

        allocated_qry = context.session.query(models_v2.IPAllocation)
        # recycle all of the IP's
        # NOTE(garyk) this may be have to be addressed differently when
        # working with a DHCP server.
        allocated = allocated_qry.filter_by(port_id=id).all()
        if allocated:
            for a in allocated:
                subnet = self._get_subnet(context, a['subnet_id'])
                if a['ip_address'] == subnet['gateway_ip']:
                    # Gateway address will not be recycled, but we do
                    # need to delete the allocation from the DB
                    QuantumDbPluginV2._delete_ip_allocation(
                        context, a['network_id'],
                        a['subnet_id'], a['ip_address'])
                    LOG.debug("Gateway address (%s/%s) is not recycled",
                              a['ip_address'], a['subnet_id'])
                    continue

                QuantumDbPluginV2._hold_ip(context,
                                           a['network_id'],
                                           a['subnet_id'],
                                           id,
                                           a['ip_address'])
        context.session.delete(port)

    def get_port(self, context, id, fields=None):
        port = self._get_port(context, id)
        return self._make_port_dict(port, fields)

    def get_ports(self, context, filters=None, fields=None):
        Port = models_v2.Port
        IPAllocation = models_v2.IPAllocation

        if not filters:
            filters = {}

        query = self._model_query(context, Port)

        fixed_ips = filters.pop('fixed_ips', {})
        ip_addresses = fixed_ips.get('ip_address')
        subnet_ids = fixed_ips.get('subnet_id')
        if ip_addresses or subnet_ids:
            query = query.join(Port.fixed_ips)
            if ip_addresses:
                query = query.filter(IPAllocation.ip_address.in_(ip_addresses))
            if subnet_ids:
                query = query.filter(IPAllocation.subnet_id.in_(subnet_ids))

        query = self._apply_filters_to_query(query, Port, filters)
        return [self._make_port_dict(c, fields) for c in query.all()]
