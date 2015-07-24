# Copyright (c) 2015 Infoblox Inc.
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
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy import and_

from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.common import ipv6_utils
from neutron.db import ipam_backend_mixin
from neutron.db import models_v2
from neutron.i18n import _LE
from neutron.ipam import driver
from neutron.ipam import exceptions as ipam_exc
from neutron.ipam import requests as ipam_req


LOG = logging.getLogger(__name__)


class IpamPluggableBackend(ipam_backend_mixin.IpamBackendMixin):

    def _get_failed_ips(self, all_ips, success_ips):
        ips_list = (ip_dict['ip_address'] for ip_dict in success_ips)
        return (ip_dict['ip_address'] for ip_dict in all_ips
                if ip_dict['ip_address'] not in ips_list)

    def _ipam_deallocate_ips(self, context, ipam_driver, port, ips,
                             revert_on_fail=True):
        """Deallocate set of ips over IPAM.

        If any single ip deallocation fails, tries to allocate deallocated
        ip addresses with fixed ip request
        """
        deallocated = []

        try:
            for ip in ips:
                try:
                    ipam_subnet = ipam_driver.get_subnet(ip['subnet_id'])
                    ipam_subnet.deallocate(ip['ip_address'])
                    deallocated.append(ip)
                except n_exc.SubnetNotFound:
                    LOG.debug("Subnet was not found on ip deallocation: %s",
                              ip)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.debug("An exception occurred during IP deallocation.")
                if revert_on_fail and deallocated:
                    LOG.debug("Reverting deallocation")
                    self._ipam_allocate_ips(context, ipam_driver, port,
                                            deallocated, revert_on_fail=False)
                elif not revert_on_fail and ips:
                    addresses = ', '.join(self._get_failed_ips(ips,
                                                               deallocated))
                    LOG.error(_LE("IP deallocation failed on "
                                  "external system for %s"), addresses)
        return deallocated

    def _ipam_try_allocate_ip(self, context, ipam_driver, port, ip_dict):
        factory = ipam_driver.get_address_request_factory()
        ip_request = factory.get_request(context, port, ip_dict)
        ipam_subnet = ipam_driver.get_subnet(ip_dict['subnet_id'])
        return ipam_subnet.allocate(ip_request)

    def _ipam_allocate_single_ip(self, context, ipam_driver, port, subnets):
        """Allocates single ip from set of subnets

        Raises n_exc.IpAddressGenerationFailure if allocation failed for
        all subnets.
        """
        for subnet in subnets:
            try:
                return [self._ipam_try_allocate_ip(context, ipam_driver,
                                                   port, subnet),
                        subnet]
            except ipam_exc.IpAddressGenerationFailure:
                continue
        raise n_exc.IpAddressGenerationFailure(
            net_id=port['network_id'])

    def _ipam_allocate_ips(self, context, ipam_driver, port, ips,
                           revert_on_fail=True):
        """Allocate set of ips over IPAM.

        If any single ip allocation fails, tries to deallocate all
        allocated ip addresses.
        """
        allocated = []

        # we need to start with entries that asked for a specific IP in case
        # those IPs happen to be next in the line for allocation for ones that
        # didn't ask for a specific IP
        ips.sort(key=lambda x: 'ip_address' not in x)
        try:
            for ip in ips:
                # By default IP info is dict, used to allocate single ip
                # from single subnet.
                # IP info can be list, used to allocate single ip from
                # multiple subnets (i.e. first successful ip allocation
                # is returned)
                ip_list = [ip] if isinstance(ip, dict) else ip
                ip_address, ip_subnet = self._ipam_allocate_single_ip(
                    context, ipam_driver, port, ip_list)
                allocated.append({'ip_address': ip_address,
                                  'subnet_id': ip_subnet['subnet_id']})
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.debug("An exception occurred during IP allocation.")

                if revert_on_fail and allocated:
                    LOG.debug("Reverting allocation")
                    self._ipam_deallocate_ips(context, ipam_driver, port,
                                              allocated, revert_on_fail=False)
                elif not revert_on_fail and ips:
                    addresses = ', '.join(self._get_failed_ips(ips,
                                                               allocated))
                    LOG.error(_LE("IP allocation failed on "
                                  "external system for %s"), addresses)

        return allocated

    def _ipam_update_allocation_pools(self, context, ipam_driver, subnet):
        self._validate_allocation_pools(subnet['allocation_pools'],
                                        subnet['cidr'])

        factory = ipam_driver.get_subnet_request_factory()
        subnet_request = factory.get_request(context, subnet, None)

        ipam_driver.update_subnet(subnet_request)

    def delete_subnet(self, context, subnet_id):
        ipam_driver = driver.Pool.get_instance(None, context)
        ipam_driver.remove_subnet(subnet_id)

    def allocate_ips_for_port_and_store(self, context, port, port_id):
        network_id = port['port']['network_id']
        ips = []
        try:
            ips = self._allocate_ips_for_port(context, port)
            for ip in ips:
                ip_address = ip['ip_address']
                subnet_id = ip['subnet_id']
                IpamPluggableBackend._store_ip_allocation(
                    context, ip_address, network_id,
                    subnet_id, port_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                if ips:
                    LOG.debug("An exception occurred during port creation."
                              "Reverting IP allocation")
                    ipam_driver = driver.Pool.get_instance(None, context)
                    self._ipam_deallocate_ips(context, ipam_driver,
                                              port['port'], ips,
                                              revert_on_fail=False)

    def _allocate_ips_for_port(self, context, port):
        """Allocate IP addresses for the port. IPAM version.

        If port['fixed_ips'] is set to 'ATTR_NOT_SPECIFIED', allocate IP
        addresses for the port. If port['fixed_ips'] contains an IP address or
        a subnet_id then allocate an IP address accordingly.
        """
        p = port['port']
        ips = []
        v6_stateless = []
        net_id_filter = {'network_id': [p['network_id']]}
        subnets = self._get_subnets(context, filters=net_id_filter)
        is_router_port = (
            p['device_owner'] in constants.ROUTER_INTERFACE_OWNERS_SNAT)

        fixed_configured = p['fixed_ips'] is not attributes.ATTR_NOT_SPECIFIED
        if fixed_configured:
            ips = self._test_fixed_ips_for_port(context,
                                                p["network_id"],
                                                p['fixed_ips'],
                                                p['device_owner'])
            # For ports that are not router ports, implicitly include all
            # auto-address subnets for address association.
            if not is_router_port:
                v6_stateless += [subnet for subnet in subnets
                                 if ipv6_utils.is_auto_address_subnet(subnet)]
        else:
            # Split into v4, v6 stateless and v6 stateful subnets
            v4 = []
            v6_stateful = []
            for subnet in subnets:
                if subnet['ip_version'] == 4:
                    v4.append(subnet)
                else:
                    if ipv6_utils.is_auto_address_subnet(subnet):
                        if not is_router_port:
                            v6_stateless.append(subnet)
                    else:
                        v6_stateful.append(subnet)

            version_subnets = [v4, v6_stateful]
            for subnets in version_subnets:
                if subnets:
                    ips.append([{'subnet_id': s['id']}
                                for s in subnets])

        for subnet in v6_stateless:
            # IP addresses for IPv6 SLAAC and DHCPv6-stateless subnets
            # are implicitly included.
            ips.append({'subnet_id': subnet['id'],
                        'subnet_cidr': subnet['cidr'],
                        'eui64_address': True,
                        'mac': p['mac_address']})
        ipam_driver = driver.Pool.get_instance(None, context)
        return self._ipam_allocate_ips(context, ipam_driver, p, ips)

    def _test_fixed_ips_for_port(self, context, network_id, fixed_ips,
                                 device_owner):
        """Test fixed IPs for port.

        Check that configured subnets are valid prior to allocating any
        IPs. Include the subnet_id in the result if only an IP address is
        configured.

        :raises: InvalidInput, IpAddressInUse, InvalidIpForNetwork,
                 InvalidIpForSubnet
        """
        fixed_ip_list = []
        for fixed in fixed_ips:
            subnet = self._get_subnet_for_fixed_ip(context, fixed, network_id)

            is_auto_addr_subnet = ipv6_utils.is_auto_address_subnet(subnet)
            if 'ip_address' in fixed:
                if (is_auto_addr_subnet and device_owner not in
                        constants.ROUTER_INTERFACE_OWNERS):
                    msg = (_("IPv6 address %(address)s can not be directly "
                            "assigned to a port on subnet %(id)s since the "
                            "subnet is configured for automatic addresses") %
                           {'address': fixed['ip_address'],
                            'id': subnet['id']})
                    raise n_exc.InvalidInput(error_message=msg)
                fixed_ip_list.append({'subnet_id': subnet['id'],
                                      'ip_address': fixed['ip_address']})
            else:
                # A scan for auto-address subnets on the network is done
                # separately so that all such subnets (not just those
                # listed explicitly here by subnet ID) are associated
                # with the port.
                if (device_owner in constants.ROUTER_INTERFACE_OWNERS_SNAT or
                        not is_auto_addr_subnet):
                    fixed_ip_list.append({'subnet_id': subnet['id']})

        self._validate_max_ips_per_port(fixed_ip_list)
        return fixed_ip_list

    def _update_ips_for_port(self, context, port,
                             original_ips, new_ips, mac):
        """Add or remove IPs from the port. IPAM version"""
        added = []
        removed = []
        changes = self._get_changed_ips_for_port(
            context, original_ips, new_ips, port['device_owner'])
        # Check if the IP's to add are OK
        to_add = self._test_fixed_ips_for_port(
            context, port['network_id'], changes.add,
            port['device_owner'])

        ipam_driver = driver.Pool.get_instance(None, context)
        if changes.remove:
            removed = self._ipam_deallocate_ips(context, ipam_driver, port,
                                                changes.remove)
        if to_add:
            added = self._ipam_allocate_ips(context, ipam_driver,
                                            changes, to_add)
        return self.Changes(add=added,
                            original=changes.original,
                            remove=removed)

    def save_allocation_pools(self, context, subnet, allocation_pools):
        for pool in allocation_pools:
            first_ip = str(netaddr.IPAddress(pool.first, pool.version))
            last_ip = str(netaddr.IPAddress(pool.last, pool.version))
            ip_pool = models_v2.IPAllocationPool(subnet=subnet,
                                                 first_ip=first_ip,
                                                 last_ip=last_ip)
            context.session.add(ip_pool)

    def update_port_with_ips(self, context, db_port, new_port, new_mac):
        changes = self.Changes(add=[], original=[], remove=[])

        if 'fixed_ips' in new_port:
            original = self._make_port_dict(db_port,
                                            process_extensions=False)
            changes = self._update_ips_for_port(context,
                                                db_port,
                                                original["fixed_ips"],
                                                new_port['fixed_ips'],
                                                new_mac)
        try:
            # Check if the IPs need to be updated
            network_id = db_port['network_id']
            for ip in changes.add:
                self._store_ip_allocation(
                    context, ip['ip_address'], network_id,
                    ip['subnet_id'], db_port.id)
            for ip in changes.remove:
                self._delete_ip_allocation(context, network_id,
                                           ip['subnet_id'], ip['ip_address'])
            self._update_db_port(context, db_port, new_port, network_id,
                                 new_mac)
        except Exception:
            with excutils.save_and_reraise_exception():
                if 'fixed_ips' in new_port:
                    LOG.debug("An exception occurred during port update.")
                    ipam_driver = driver.Pool.get_instance(None, context)
                    if changes.add:
                        LOG.debug("Reverting IP allocation.")
                        self._ipam_deallocate_ips(context, ipam_driver,
                                                  db_port, changes.add,
                                                  revert_on_fail=False)
                    if changes.remove:
                        LOG.debug("Reverting IP deallocation.")
                        self._ipam_allocate_ips(context, ipam_driver,
                                                db_port, changes.remove,
                                                revert_on_fail=False)
        return changes

    def delete_port(self, context, id):
        # Get fixed_ips list before port deletion
        port = self._get_port(context, id)
        ipam_driver = driver.Pool.get_instance(None, context)

        super(IpamPluggableBackend, self).delete_port(context, id)
        # Deallocating ips via IPAM after port is deleted locally.
        # So no need to do rollback actions on remote server
        # in case of fail to delete port locally
        self._ipam_deallocate_ips(context, ipam_driver, port,
                                  port['fixed_ips'])

    def update_db_subnet(self, context, id, s, old_pools):
        ipam_driver = driver.Pool.get_instance(None, context)
        if "allocation_pools" in s:
            self._ipam_update_allocation_pools(context, ipam_driver, s)

        try:
            subnet, changes = super(IpamPluggableBackend,
                                    self).update_db_subnet(context, id,
                                                           s, old_pools)
        except Exception:
            with excutils.save_and_reraise_exception():
                if "allocation_pools" in s and old_pools:
                    LOG.error(
                        _LE("An exception occurred during subnet update."
                            "Reverting allocation pool changes"))
                    s['allocation_pools'] = old_pools
                    self._ipam_update_allocation_pools(context, ipam_driver, s)
        return subnet, changes

    def add_auto_addrs_on_network_ports(self, context, subnet, ipam_subnet):
        """For an auto-address subnet, add addrs for ports on the net."""
        with context.session.begin(subtransactions=True):
            network_id = subnet['network_id']
            port_qry = context.session.query(models_v2.Port)
            ports = port_qry.filter(
                and_(models_v2.Port.network_id == network_id,
                     ~models_v2.Port.device_owner.in_(
                         constants.ROUTER_INTERFACE_OWNERS_SNAT)))
            for port in ports:
                ip_request = ipam_req.AutomaticAddressRequest(
                    prefix=subnet['cidr'],
                    mac=port['mac_address'])
                ip_address = ipam_subnet.allocate(ip_request)
                allocated = models_v2.IPAllocation(network_id=network_id,
                                                   port_id=port['id'],
                                                   ip_address=ip_address,
                                                   subnet_id=subnet['id'])
                try:
                    # Do the insertion of each IP allocation entry within
                    # the context of a nested transaction, so that the entry
                    # is rolled back independently of other entries whenever
                    # the corresponding port has been deleted.
                    with context.session.begin_nested():
                        context.session.add(allocated)
                except db_exc.DBReferenceError:
                    LOG.debug("Port %s was deleted while updating it with an "
                              "IPv6 auto-address. Ignoring.", port['id'])
                    LOG.debug("Reverting IP allocation for %s", ip_address)
                    # Do not fail if reverting allocation was unsuccessful
                    try:
                        ipam_subnet.deallocate(ip_address)
                    except Exception:
                        LOG.debug("Reverting IP allocation failed for %s",
                                  ip_address)

    def allocate_subnet(self, context, network, subnet, subnetpool_id):
        subnetpool = None

        if subnetpool_id:
            subnetpool = self._get_subnetpool(context, subnetpool_id)
            self._validate_ip_version_with_subnetpool(subnet, subnetpool)

        # gateway_ip and allocation pools should be validated or generated
        # only for specific request
        if subnet['cidr'] is not attributes.ATTR_NOT_SPECIFIED:
            subnet['gateway_ip'] = self._gateway_ip_str(subnet,
                                                        subnet['cidr'])
            subnet['allocation_pools'] = self._prepare_allocation_pools(
                subnet['allocation_pools'],
                subnet['cidr'],
                subnet['gateway_ip'])

        ipam_driver = driver.Pool.get_instance(subnetpool, context)
        subnet_factory = ipam_driver.get_subnet_request_factory()
        subnet_request = subnet_factory.get_request(context, subnet,
                                                    subnetpool)
        ipam_subnet = ipam_driver.allocate_subnet(subnet_request)
        # get updated details with actually allocated subnet
        subnet_request = ipam_subnet.get_details()

        try:
            subnet = self._save_subnet(context,
                                       network,
                                       self._make_subnet_args(
                                           subnet_request,
                                           subnet,
                                           subnetpool_id),
                                       subnet['dns_nameservers'],
                                       subnet['host_routes'],
                                       subnet_request)
        except Exception:
            # Note(pbondar): Third-party ipam servers can't rely
            # on transaction rollback, so explicit rollback call needed.
            # IPAM part rolled back in exception handling
            # and subnet part is rolled back by transaction rollback.
            with excutils.save_and_reraise_exception():
                LOG.debug("An exception occurred during subnet creation."
                          "Reverting subnet allocation.")
                self.delete_subnet(context, subnet_request.subnet_id)
        return subnet, ipam_subnet
