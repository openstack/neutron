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

from oslo_log import log as logging
from oslo_utils import excutils

from neutron.common import exceptions as n_exc
from neutron.db import ipam_backend_mixin
from neutron.i18n import _LE
from neutron.ipam import exceptions as ipam_exc


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
                                  'subnet_cidr': ip_subnet['subnet_cidr'],
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
