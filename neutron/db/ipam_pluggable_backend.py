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

import copy

import netaddr
from neutron_lib.api.definitions import portbindings
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from oslo_db import exception as db_exc
from oslo_log import log as logging
from oslo_utils import excutils
from sqlalchemy import and_

from neutron.common import ipv6_utils
from neutron.db import api as db_api
from neutron.db import ipam_backend_mixin
from neutron.db import models_v2
from neutron.ipam import driver
from neutron.ipam import exceptions as ipam_exc
from neutron.objects import ports as port_obj
from neutron.objects import subnet as obj_subnet


LOG = logging.getLogger(__name__)


class IpamPluggableBackend(ipam_backend_mixin.IpamBackendMixin):

    def _get_failed_ips(self, all_ips, success_ips):
        ips_list = (ip_dict['ip_address'] for ip_dict in success_ips)
        return (ip_dict['ip_address'] for ip_dict in all_ips
                if ip_dict['ip_address'] not in ips_list)

    def _safe_rollback(self, func, *args, **kwargs):
        """Calls rollback actions and catch all exceptions.

        All exceptions are catched and logged here to prevent rewriting
        original exception that triggered rollback action.
        """
        try:
            func(*args, **kwargs)
        except Exception as e:
            LOG.warning("Revert failed with: %s", e)

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
                if not ipam_driver.needs_rollback():
                    return

                LOG.debug("An exception occurred during IP deallocation.")
                if revert_on_fail and deallocated:
                    LOG.debug("Reverting deallocation")
                    # In case of deadlock allocate fails with db error
                    # and rewrites original exception preventing db_retry
                    # wrappers from restarting entire api request.
                    self._safe_rollback(self._ipam_allocate_ips, context,
                                        ipam_driver, port, deallocated,
                                        revert_on_fail=False)
                elif not revert_on_fail and ips:
                    addresses = ', '.join(self._get_failed_ips(ips,
                                                               deallocated))
                    LOG.error("IP deallocation failed on "
                              "external system for %s", addresses)
        return deallocated

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
                # multiple subnets
                ip_list = [ip] if isinstance(ip, dict) else ip
                subnets = [ip_dict['subnet_id'] for ip_dict in ip_list]
                try:
                    factory = ipam_driver.get_address_request_factory()
                    ip_request = factory.get_request(context, port, ip_list[0])
                    ipam_allocator = ipam_driver.get_allocator(subnets)
                    ip_address, subnet_id = ipam_allocator.allocate(ip_request)
                except ipam_exc.IpAddressGenerationFailureAllSubnets:
                    raise n_exc.IpAddressGenerationFailure(
                        net_id=port['network_id'])

                allocated.append({'ip_address': ip_address,
                                  'subnet_id': subnet_id})
        except Exception:
            with excutils.save_and_reraise_exception():
                if not ipam_driver.needs_rollback():
                    return

                LOG.debug("An exception occurred during IP allocation.")

                if revert_on_fail and allocated:
                    LOG.debug("Reverting allocation")
                    # In case of deadlock deallocation fails with db error
                    # and rewrites original exception preventing db_retry
                    # wrappers from restarting entire api request.
                    self._safe_rollback(self._ipam_deallocate_ips, context,
                                        ipam_driver, port, allocated,
                                        revert_on_fail=False)
                elif not revert_on_fail and ips:
                    addresses = ', '.join(self._get_failed_ips(ips,
                                                               allocated))
                    LOG.error("IP allocation failed on "
                              "external system for %s", addresses)

        return allocated

    def _ipam_update_allocation_pools(self, context, ipam_driver, subnet):
        factory = ipam_driver.get_subnet_request_factory()
        subnet_request = factory.get_request(context, subnet, None)

        ipam_driver.update_subnet(subnet_request)

    def delete_subnet(self, context, subnet_id):
        ipam_driver = driver.Pool.get_instance(None, context)
        ipam_driver.remove_subnet(subnet_id)

    def get_subnet(self, context, subnet_id):
        ipam_driver = driver.Pool.get_instance(None, context)
        return ipam_driver.get_subnet(subnet_id)

    def allocate_ips_for_port_and_store(self, context, port, port_id):
        # Make a copy of port dict to prevent changing
        # incoming dict by adding 'id' to it.
        # Deepcopy doesn't work correctly in this case, because copy of
        # ATTR_NOT_SPECIFIED object happens. Address of copied object doesn't
        # match original object, so 'is' check fails
        port_copy = {'port': port['port'].copy()}
        port_copy['port']['id'] = port_id
        network_id = port_copy['port']['network_id']
        ips = []
        try:
            ips = self._allocate_ips_for_port(context, port_copy)
            for ip in ips:
                ip_address = ip['ip_address']
                subnet_id = ip['subnet_id']
                IpamPluggableBackend._store_ip_allocation(
                    context, ip_address, network_id,
                    subnet_id, port_id)
            return ips
        except Exception:
            with excutils.save_and_reraise_exception():
                if ips:
                    ipam_driver = driver.Pool.get_instance(None, context)
                    if not ipam_driver.needs_rollback():
                        return

                    LOG.debug("An exception occurred during port creation. "
                              "Reverting IP allocation")
                    self._safe_rollback(self._ipam_deallocate_ips, context,
                                        ipam_driver, port_copy['port'], ips,
                                        revert_on_fail=False)

    def _allocate_ips_for_port(self, context, port):
        """Allocate IP addresses for the port. IPAM version.

        If port['fixed_ips'] is set to 'ATTR_NOT_SPECIFIED', allocate IP
        addresses for the port. If port['fixed_ips'] contains an IP address or
        a subnet_id then allocate an IP address accordingly.
        """
        p = port['port']
        fixed_configured = p['fixed_ips'] is not constants.ATTR_NOT_SPECIFIED
        subnets = self._ipam_get_subnets(context,
                                         network_id=p['network_id'],
                                         host=p.get(portbindings.HOST_ID),
                                         service_type=p.get('device_owner'),
                                         fixed_configured=fixed_configured)

        v4, v6_stateful, v6_stateless = self._classify_subnets(
            context, subnets)

        if fixed_configured:
            ips = self._test_fixed_ips_for_port(context,
                                                p["network_id"],
                                                p['fixed_ips'],
                                                p['device_owner'],
                                                subnets)
        else:
            ips = []
            version_subnets = [v4, v6_stateful]
            for subnets in version_subnets:
                if subnets:
                    ips.append([{'subnet_id': s['id']}
                                for s in subnets])

        ips.extend(self._get_auto_address_ips(v6_stateless, p))

        ipam_driver = driver.Pool.get_instance(None, context)
        return self._ipam_allocate_ips(context, ipam_driver, p, ips)

    def _get_auto_address_ips(self, v6_stateless_subnets, port,
                              exclude_subnet_ids=None):
        exclude_subnet_ids = exclude_subnet_ids or []
        ips = []
        is_router_port = (
            port['device_owner'] in constants.ROUTER_INTERFACE_OWNERS_SNAT)
        if not is_router_port:
            for subnet in v6_stateless_subnets:
                if subnet['id'] not in exclude_subnet_ids:
                    # IP addresses for IPv6 SLAAC and DHCPv6-stateless subnets
                    # are implicitly included.
                    ips.append({'subnet_id': subnet['id'],
                                'subnet_cidr': subnet['cidr'],
                                'eui64_address': True,
                                'mac': port['mac_address']})
        return ips

    def _test_fixed_ips_for_port(self, context, network_id, fixed_ips,
                                 device_owner, subnets):
        """Test fixed IPs for port.

        Check that configured subnets are valid prior to allocating any
        IPs. Include the subnet_id in the result if only an IP address is
        configured.

        :raises: InvalidInput, IpAddressInUse, InvalidIpForNetwork,
                 InvalidIpForSubnet
        """
        fixed_ip_list = []
        for fixed in fixed_ips:
            fixed['device_owner'] = device_owner
            subnet = self._get_subnet_for_fixed_ip(context, fixed, subnets)

            is_auto_addr_subnet = ipv6_utils.is_auto_address_subnet(subnet)
            if ('ip_address' in fixed and
                    subnet['cidr'] != constants.PROVISIONAL_IPV6_PD_PREFIX):
                if (is_auto_addr_subnet and device_owner not in
                        constants.ROUTER_INTERFACE_OWNERS):
                    raise ipam_exc.AllocationOnAutoAddressSubnet(
                        ip=fixed['ip_address'], subnet_id=subnet['id'])
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

        return fixed_ip_list

    def _update_ips_for_port(self, context, port, host,
                             original_ips, new_ips, mac):
        """Add or remove IPs from the port. IPAM version"""
        added = []
        removed = []
        changes = self._get_changed_ips_for_port(
            context, original_ips, new_ips, port['device_owner'])
        try:
            subnets = self._ipam_get_subnets(
                context, network_id=port['network_id'], host=host,
                service_type=port.get('device_owner'))
        except ipam_exc.DeferIpam:
            subnets = []

        # Check if the IP's to add are OK
        to_add = self._test_fixed_ips_for_port(
            context, port['network_id'], changes.add,
            port['device_owner'], subnets)

        if port['device_owner'] not in constants.ROUTER_INTERFACE_OWNERS:
            to_add += self._update_ips_for_pd_subnet(
                context, subnets, changes.add, mac)

        ipam_driver = driver.Pool.get_instance(None, context)
        if changes.remove:
            removed = self._ipam_deallocate_ips(context, ipam_driver, port,
                                                changes.remove)

        v6_stateless = self._classify_subnets(
            context, subnets)[2]
        handled_subnet_ids = [ip['subnet_id'] for ip in
                              to_add + changes.original + changes.remove]
        to_add.extend(self._get_auto_address_ips(
            v6_stateless, port, handled_subnet_ids))

        if to_add:
            added = self._ipam_allocate_ips(context, ipam_driver,
                                            port, to_add)
        return self.Changes(add=added,
                            original=changes.original,
                            remove=removed)

    @db_api.context_manager.writer
    def save_allocation_pools(self, context, subnet, allocation_pools):
        for pool in allocation_pools:
            first_ip = str(netaddr.IPAddress(pool.first, pool.version))
            last_ip = str(netaddr.IPAddress(pool.last, pool.version))
            obj_subnet.IPAllocationPool(
                context, subnet_id=subnet['id'], start=first_ip,
                end=last_ip).create()

    def update_port_with_ips(self, context, host, db_port, new_port, new_mac):
        changes = self.Changes(add=[], original=[], remove=[])

        auto_assign_subnets = []
        if new_mac:
            original = self._make_port_dict(db_port, process_extensions=False)
            if original.get('mac_address') != new_mac:
                original_ips = original.get('fixed_ips', [])
                # NOTE(hjensas): Only set the default for 'fixed_ips' in
                # new_port if the original port or new_port actually have IPs.
                # Setting the default to [] breaks deferred IP allocation.
                # See Bug: https://bugs.launchpad.net/neutron/+bug/1811905
                if original_ips or new_port.get('fixed_ips'):
                    new_ips = new_port.setdefault('fixed_ips', original_ips)
                    new_ips_subnets = [new_ip['subnet_id']
                                       for new_ip in new_ips]
                for orig_ip in original_ips:
                    if ipv6_utils.is_eui64_address(orig_ip.get('ip_address')):
                        subnet_to_delete = {}
                        subnet_to_delete['subnet_id'] = orig_ip['subnet_id']
                        subnet_to_delete['delete_subnet'] = True
                        auto_assign_subnets.append(subnet_to_delete)
                        try:
                            i = new_ips_subnets.index(orig_ip['subnet_id'])
                            new_ips[i] = subnet_to_delete
                        except ValueError:
                            new_ips.append(subnet_to_delete)

        if 'fixed_ips' in new_port:
            original = self._make_port_dict(db_port,
                                            process_extensions=False)
            changes = self._update_ips_for_port(context,
                                                db_port,
                                                host,
                                                original["fixed_ips"],
                                                new_port['fixed_ips'],
                                                new_mac)
        try:
            # Expire the fixed_ips of db_port in current transaction, because
            # it will be changed in the following operation and the latest
            # data is expected.
            context.session.expire(db_port, ['fixed_ips'])

            # Check if the IPs need to be updated
            network_id = db_port['network_id']
            for ip in changes.remove:
                self._delete_ip_allocation(context, network_id,
                                           ip['subnet_id'], ip['ip_address'])
            for ip in changes.add:
                self._store_ip_allocation(
                    context, ip['ip_address'], network_id,
                    ip['subnet_id'], db_port.id)
            self._update_db_port(context, db_port, new_port, network_id,
                                 new_mac)

            if auto_assign_subnets:
                port_copy = copy.deepcopy(original)
                port_copy.update(new_port)
                port_copy['fixed_ips'] = auto_assign_subnets
                self.allocate_ips_for_port_and_store(context,
                            {'port': port_copy}, port_copy['id'])

            getattr(db_port, 'fixed_ips')  # refresh relationship before return

        except Exception:
            with excutils.save_and_reraise_exception():
                if 'fixed_ips' in new_port:
                    ipam_driver = driver.Pool.get_instance(None, context)
                    if not ipam_driver.needs_rollback():
                        return

                    LOG.debug("An exception occurred during port update.")
                    if changes.add:
                        LOG.debug("Reverting IP allocation.")
                        self._safe_rollback(self._ipam_deallocate_ips,
                                            context,
                                            ipam_driver,
                                            db_port,
                                            changes.add,
                                            revert_on_fail=False)
                    if changes.remove:
                        LOG.debug("Reverting IP deallocation.")
                        self._safe_rollback(self._ipam_allocate_ips,
                                            context,
                                            ipam_driver,
                                            db_port,
                                            changes.remove,
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
        # 'allocation_pools' is removed from 's' in
        # _update_subnet_allocation_pools (ipam_backend_mixin),
        # so create unchanged copy for ipam driver
        subnet_copy = copy.deepcopy(s)
        subnet, changes = super(IpamPluggableBackend, self).update_db_subnet(
            context, id, s, old_pools)
        ipam_driver = driver.Pool.get_instance(None, context)

        # Set old allocation pools if no new pools are provided by user.
        # Passing old pools allows to call ipam driver on each subnet update
        # even if allocation pools are not changed. So custom ipam drivers
        # are able to track other fields changes on subnet update.
        if 'allocation_pools' not in subnet_copy:
            subnet_copy['allocation_pools'] = old_pools
        self._ipam_update_allocation_pools(context, ipam_driver, subnet_copy)

        return subnet, changes

    def add_auto_addrs_on_network_ports(self, context, subnet, ipam_subnet):
        """For an auto-address subnet, add addrs for ports on the net."""
        # TODO(ataraday): switched for writer when flush_on_subtransaction
        # will be available for neutron
        with context.session.begin(subtransactions=True):
            network_id = subnet['network_id']
            port_qry = context.session.query(models_v2.Port)
            ports = port_qry.filter(
                and_(models_v2.Port.network_id == network_id,
                     ~models_v2.Port.device_owner.in_(
                         constants.ROUTER_INTERFACE_OWNERS_SNAT)))
            updated_ports = []
            ipam_driver = driver.Pool.get_instance(None, context)
            factory = ipam_driver.get_address_request_factory()
            for port in ports:
                ip = {'subnet_id': subnet['id'],
                      'subnet_cidr': subnet['cidr'],
                      'eui64_address': True,
                      'mac': port['mac_address']}
                ip_request = factory.get_request(context, port, ip)
                try:
                    ip_address = ipam_subnet.allocate(ip_request)
                    allocated = port_obj.IPAllocation(
                        context, network_id=network_id, port_id=port['id'],
                        ip_address=ip_address, subnet_id=subnet['id'])
                    # Do the insertion of each IP allocation entry within
                    # the context of a nested transaction, so that the entry
                    # is rolled back independently of other entries whenever
                    # the corresponding port has been deleted; since OVO
                    # already opens a nested transaction, we don't need to do
                    # it explicitly here.
                    allocated.create()
                    updated_ports.append(port['id'])
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
                except ipam_exc.IpAddressAlreadyAllocated:
                    LOG.debug("Port %s got IPv6 auto-address in a concurrent "
                              "create or update port request. Ignoring.",
                              port['id'])
            return updated_ports

    def allocate_subnet(self, context, network, subnet, subnetpool_id):
        subnetpool = None

        if subnetpool_id and not subnetpool_id == constants.IPV6_PD_POOL_ID:
            subnetpool = self._get_subnetpool(context, id=subnetpool_id)
            self._validate_ip_version_with_subnetpool(subnet, subnetpool)

        # gateway_ip and allocation pools should be validated or generated
        # only for specific request
        if subnet['cidr'] is not constants.ATTR_NOT_SPECIFIED:
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
                if not ipam_driver.needs_rollback():
                    return

                LOG.debug("An exception occurred during subnet creation. "
                          "Reverting subnet allocation.")
                self._safe_rollback(self.delete_subnet,
                                    context,
                                    subnet_request.subnet_id)
        return subnet, ipam_subnet
