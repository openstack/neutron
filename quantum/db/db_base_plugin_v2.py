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

import logging
import random

import netaddr
from sqlalchemy import orm
from sqlalchemy.orm import exc

from quantum.api.v2 import router as api_router
from quantum.common import exceptions as q_exc
from quantum.db import api as db
from quantum.db import models_v2
from quantum.openstack.common import cfg
from quantum import quantum_plugin_base_v2


LOG = logging.getLogger(__name__)


class QuantumDbPluginV2(quantum_plugin_base_v2.QuantumPluginBaseV2):
    """ A class that implements the v2 Quantum plugin interface
        using SQLAlchemy models.  Whenever a non-read call happens
        the plugin will call an event handler class method (e.g.,
        network_created()).  The result is that this class can be
        sub-classed by other classes that add custom behaviors on
        certain events.
    """

    def __init__(self):
        # NOTE(jkoelker) This is an incomlete implementation. Subclasses
        #                must override __init__ and setup the database
        #                and not call into this class's __init__.
        #                This connection is setup as memory for the tests.
        sql_connection = 'sqlite:///:memory:'
        db.configure_db({'sql_connection': sql_connection,
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

        # NOTE(jkoelker) non-admin queries are scoped to their tenant_id
        if not context.is_admin and hasattr(model.tenant_id):
            query = query.filter(tenant_id=context.tenant_id)

        return query

    def _get_by_id(self, context, model, id, joins=(), verbose=None):
        query = self._model_query(context, model)
        if verbose:
            if verbose and isinstance(verbose, list):
                options = [orm.joinedload(join) for join in joins
                           if join in verbose]
            else:
                options = [orm.joinedload(join) for join in joins]
            query = query.options(*options)
        return query.filter_by(id=id).one()

    def _get_network(self, context, id, verbose=None):
        try:
            network = self._get_by_id(context, models_v2.Network, id,
                                      joins=('subnets',), verbose=verbose)
        except exc.NoResultFound:
            raise q_exc.NetworkNotFound(net_id=id)
        except exc.MultipleResultsFound:
            LOG.error('Multiple networks match for %s' % id)
            raise q_exc.NetworkNotFound(net_id=id)
        return network

    def _get_subnet(self, context, id, verbose=None):
        try:
            subnet = self._get_by_id(context, models_v2.Subnet, id,
                                     verbose=verbose)
        except exc.NoResultFound:
            raise q_exc.SubnetNotFound(subnet_id=id)
        except exc.MultipleResultsFound:
            LOG.error('Multiple subnets match for %s' % id)
            raise q_exc.SubnetNotFound(subnet_id=id)
        return subnet

    def _get_port(self, context, id, verbose=None):
        try:
            port = self._get_by_id(context, models_v2.Port, id,
                                   verbose=verbose)
        except exc.NoResultFound:
            # NOTE(jkoelker) The PortNotFound exceptions requires net_id
            #                kwarg in order to set the message correctly
            raise q_exc.PortNotFound(port_id=id, net_id=None)
        except exc.MultipleResultsFound:
            LOG.error('Multiple ports match for %s' % id)
            raise q_exc.PortNotFound(port_id=id)
        return port

    def _fields(self, resource, fields):
        if fields:
            return dict(((key, item) for key, item in resource.iteritems()
                         if key in fields))
        return resource

    def _get_collection(self, context, model, dict_func, filters=None,
                        fields=None, verbose=None):
        collection = self._model_query(context, model)
        if filters:
            for key, value in filters.iteritems():
                column = getattr(model, key, None)
                if column:
                    collection = collection.filter(column.in_(value))
        return [dict_func(c, fields) for c in collection.all()]

    @staticmethod
    def _generate_mac(context, network_id):
        base_mac = cfg.CONF.base_mac.split(':')
        max_retries = cfg.CONF.mac_generation_retries
        for i in range(max_retries):
            mac = [int(base_mac[0], 16), int(base_mac[1], 16),
                   int(base_mac[2], 16), random.randint(0x00, 0x7f),
                   random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
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
    def _recycle_ip(context, network_id, subnet_id, port_id, ip_address):
        """Return an IP address to the pool of free IP's on the network
        subnet.
        """
        range_qry = context.session.query(models_v2.IPAllocationRange)
        # Two requests will be done on the database. The first will be to
        # search if an entry starts with ip_address + 1 (r1). The second
        # will be to see if an entry ends with ip_address -1 (r2).
        # If 1 of the above holds true then the specific entry will be
        # modified. If both hold true then the two ranges will be merged.
        # If there are no entries then a single entry will be added.
        ip_first = str(netaddr.IPAddress(ip_address) + 1)
        ip_last = str(netaddr.IPAddress(ip_address) - 1)
        LOG.debug("Recycle %s", ip_address)

        try:
            r1 = range_qry.filter_by(subnet_id=subnet_id,
                                     first_ip=ip_first).one()
            LOG.debug("Recycle: first match for %s-%s", r1['first_ip'],
                      r1['last_ip'])
        except exc.NoResultFound:
            r1 = []
        try:
            r2 = range_qry.filter_by(subnet_id=subnet_id,
                                     last_ip=ip_last).one()
            LOG.debug("Recycle: last match for %s-%s", r2['first_ip'],
                      r2['last_ip'])
        except exc.NoResultFound:
            r2 = []

        if r1 and r2:
            # Merge the two ranges
            ip_range = models_v2.IPAllocationRange(subnet_id=subnet_id,
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
            ip_range = models_v2.IPAllocationRange(subnet_id=subnet_id,
                                                   first_ip=ip_address,
                                                   last_ip=ip_address)
            context.session.add(ip_range)
            LOG.debug("Recycle: created new %s-%s", ip_address, ip_address)

        # Delete the IP address from the IPAllocate table
        LOG.debug("Delete allocated IP %s (%s/%s/%s)", ip_address,
                  network_id, subnet_id, port_id)
        alloc_qry = context.session.query(models_v2.IPAllocation)
        allocated = alloc_qry.filter_by(network_id=network_id,
                                        port_id=port_id,
                                        ip_address=ip_address,
                                        subnet_id=subnet_id).delete()

    @staticmethod
    def _generate_ip(context, network_id, subnets):
        """Generate an IP address.

        The IP address will be generated from one of the subnets defined on
        the network.
        """
        range_qry = context.session.query(models_v2.IPAllocationRange)
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
        range_qry = context.session.query(models_v2.IPAllocationRange)
        ranges = range_qry.filter_by(subnet_id=subnet_id).all()
        for range in ranges:
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
                    ip_range = models_v2.IPAllocationRange(subnet_id=subnet_id,
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
            LOG.debug("Port update. Deleting %s", ip)
            QuantumDbPluginV2._recycle_ip(context,
                                          network_id=network_id,
                                          subnet_id=ip['subnet_id'],
                                          ip_address=ip['ip_address'],
                                          port_id=port_id)

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

        fixed_configured = (p['fixed_ips'] != api_router.ATTR_NOT_SPECIFIED)
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

    def _make_network_dict(self, network, fields=None):
        res = {'id': network['id'],
               'name': network['name'],
               'tenant_id': network['tenant_id'],
               'admin_state_up': network['admin_state_up'],
               'status': network['status'],
               'subnets': [subnet['id']
                           for subnet in network['subnets']]}

        return self._fields(res, fields)

    def _make_subnet_dict(self, subnet, fields=None):
        res = {'id': subnet['id'],
               'network_id': subnet['network_id'],
               'ip_version': subnet['ip_version'],
               'cidr': subnet['cidr'],
               'gateway_ip': subnet['gateway_ip']}
        return self._fields(res, fields)

    def _make_port_dict(self, port, fields=None):
        res = {"id": port["id"],
               "network_id": port["network_id"],
               'tenant_id': port['tenant_id'],
               "mac_address": port["mac_address"],
               "admin_state_up": port["admin_state_up"],
               "status": port["status"],
               "fixed_ips": [{'subnet_id': ip["subnet_id"],
                              'ip_address': ip["ip_address"]}
                             for ip in port["fixed_ips"]],
               "device_id": port["device_id"]}
        return self._fields(res, fields)

    def create_network(self, context, network):
        n = network['network']

        # NOTE(jkoelker) Get the tenant_id outside of the session to avoid
        #                unneeded db action if the operation raises
        tenant_id = self._get_tenant_id_for_create(context, n)
        with context.session.begin():
            network = models_v2.Network(tenant_id=tenant_id,
                                        name=n['name'],
                                        admin_state_up=n['admin_state_up'],
                                        status="ACTIVE")
            context.session.add(network)
        return self._make_network_dict(network)

    def update_network(self, context, id, network):
        n = network['network']
        with context.session.begin():
            network = self._get_network(context, id)
            network.update(n)
        return self._make_network_dict(network)

    def delete_network(self, context, id):
        with context.session.begin():
            network = self._get_network(context, id)

            filter = {'network_id': [id]}
            ports = self.get_ports(context, filters=filter)
            if ports:
                raise q_exc.NetworkInUse(net_id=id)

            subnets_qry = context.session.query(models_v2.Subnet)
            subnets_qry.filter_by(network_id=id).delete()
            context.session.delete(network)

    def get_network(self, context, id, fields=None, verbose=None):
        network = self._get_network(context, id, verbose=verbose)
        return self._make_network_dict(network, fields)

    def get_networks(self, context, filters=None, fields=None, verbose=None):
        return self._get_collection(context, models_v2.Network,
                                    self._make_network_dict,
                                    filters=filters, fields=fields,
                                    verbose=verbose)

    def create_subnet(self, context, subnet):
        s = subnet['subnet']

        net = netaddr.IPNetwork(s['cidr'])
        if s['gateway_ip'] == api_router.ATTR_NOT_SPECIFIED:
            s['gateway_ip'] = str(netaddr.IPAddress(net.first + 1))

        ip = netaddr.IPAddress(s['gateway_ip'])
        # Get the first and last indices for the subnet
        ranges = []
        # Gateway is the first address in the range
        if ip == net.network + 1:
            range = {'first': str(ip + 1),
                     'last': str(net.broadcast - 1)}
            ranges.append(range)
        # Gateway is the last address in the range
        elif ip == net.broadcast - 1:
            range = {'first': str(net.network + 1),
                     'last': str(ip - 1)}
            ranges.append(range)
        # Gateway is on IP in the subnet
        else:
            range = {'first': str(net.network + 1),
                     'last': str(ip - 1)}
            ranges.append(range)
            range = {'first': str(ip + 1),
                     'last': str(net.broadcast - 1)}
            ranges.append(range)
        with context.session.begin():
            network = self._get_network(context, s["network_id"])
            subnet = models_v2.Subnet(network_id=s['network_id'],
                                      ip_version=s['ip_version'],
                                      cidr=s['cidr'],
                                      gateway_ip=s['gateway_ip'])
            context.session.add(subnet)

        with context.session.begin():
            for range in ranges:
                ip_range = models_v2.IPAllocationRange(subnet_id=subnet.id,
                                                       first_ip=range['first'],
                                                       last_ip=range['last'])
                context.session.add(ip_range)
        return self._make_subnet_dict(subnet)

    def update_subnet(self, context, id, subnet):
        s = subnet['subnet']
        with context.session.begin():
            subnet = self._get_subnet(context, id)
            subnet.update(s)
        return self._make_subnet_dict(subnet)

    def delete_subnet(self, context, id):
        with context.session.begin():
            subnet = self._get_subnet(context, id)
            # Check if ports are using this subnet
            allocated_qry = context.session.query(models_v2.IPAllocation)
            allocated = allocated_qry.filter_by(subnet_id=id).all()
            if allocated:
                raise q_exc.SubnetInUse(subnet_id=id)
            # Delete IP Allocations on subnet
            range_qry = context.session.query(models_v2.IPAllocationRange)
            range_qry.filter_by(subnet_id=id).delete()
            context.session.delete(subnet)

    def get_subnet(self, context, id, fields=None, verbose=None):
        subnet = self._get_subnet(context, id, verbose=verbose)
        return self._make_subnet_dict(subnet, fields)

    def get_subnets(self, context, filters=None, fields=None, verbose=None):
        return self._get_collection(context, models_v2.Subnet,
                                    self._make_subnet_dict,
                                    filters=filters, fields=fields,
                                    verbose=verbose)

    def create_port(self, context, port):
        p = port['port']
        # NOTE(jkoelker) Get the tenant_id outside of the session to avoid
        #                unneeded db action if the operation raises
        tenant_id = self._get_tenant_id_for_create(context, p)

        with context.session.begin():
            network = self._get_network(context, p["network_id"])

            # Ensure that a MAC address is defined and it is unique on the
            # network
            if p['mac_address'] == api_router.ATTR_NOT_SPECIFIED:
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
                                  network_id=p['network_id'],
                                  mac_address=p['mac_address'],
                                  admin_state_up=p['admin_state_up'],
                                  status="ACTIVE",
                                  device_id=p['device_id'])
            context.session.add(port)

        # Update the allocated IP's
        if ips:
            with context.session.begin():
                for ip in ips:
                    LOG.debug("Allocated IP %s (%s/%s/%s)", ip['ip_address'],
                              port['network_id'], ip['subnet_id'], port.id)
                    allocated = models_v2.IPAllocation(
                        network_id=port['network_id'],
                        port_id=port.id,
                        ip_address=ip['ip_address'],
                        subnet_id=ip['subnet_id'])
                    context.session.add(allocated)

        return self._make_port_dict(port)

    def update_port(self, context, id, port):
        p = port['port']

        with context.session.begin():
            port = self._get_port(context, id)
            # Check if the IPs need to be updated
            if 'fixed_ips' in p:
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
                        ip_address=ip['ip_address'], subnet_id=ip['subnet_id'])
                    context.session.add(allocated)

            port.update(p)

        return self._make_port_dict(port)

    def delete_port(self, context, id):
        with context.session.begin():
            port = self._get_port(context, id)

            allocated_qry = context.session.query(models_v2.IPAllocation)
            # recycle all of the IP's
            # NOTE(garyk) this may be have to be addressed differently when
            # working with a DHCP server.
            allocated = allocated_qry.filter_by(port_id=id).all()
            if allocated:
                for a in allocated:
                    # Gateway address will not be recycled
                    subnet = self._get_subnet(context, a['subnet_id'])
                    if a['ip_address'] == subnet['gateway_ip']:
                        LOG.debug("Gateway address (%s/%s) is not recycled",
                                  a['ip_address'], a['subnet_id'])
                        continue

                    QuantumDbPluginV2._recycle_ip(context,
                                                  network_id=a['network_id'],
                                                  subnet_id=a['subnet_id'],
                                                  ip_address=a['ip_address'],
                                                  port_id=id)
            context.session.delete(port)

    def get_port(self, context, id, fields=None, verbose=None):
        port = self._get_port(context, id, verbose=verbose)
        return self._make_port_dict(port, fields)

    def get_ports(self, context, filters=None, fields=None, verbose=None):
        fixed_ips = filters.pop('fixed_ips', [])
        ports = self._get_collection(context, models_v2.Port,
                                     self._make_port_dict,
                                     filters=filters, fields=fields,
                                     verbose=verbose)
        if ports and fixed_ips:
            filtered_ports = []
            for port in ports:
                if port['fixed_ips']:
                    ips = port['fixed_ips']
                    for fixed in fixed_ips:
                        found = False
                        # Convert to dictionary (deserialize)
                        fixed = eval(fixed)
                        for ip in ips:
                            if 'ip_address' in fixed and 'subnet_id' in fixed:
                                if (ip['ip_address'] == fixed['ip_address'] and
                                        ip['subnet_id'] == fixed['subnet_id']):
                                    found = True
                            elif 'ip_address' in fixed:
                                if ip['ip_address'] == fixed['ip_address']:
                                    found = True
                            elif 'subnet_id' in fixed:
                                if ip['subnet_id'] == fixed['subnet_id']:
                                    found = True
                            if found:
                                filtered_ports.append(port)
                                break
                        if found:
                            break
            return filtered_ports
        return ports
