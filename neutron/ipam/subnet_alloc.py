# Copyright (c) 2015 Hewlett-Packard Co.
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

import math
import operator

import netaddr
from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.db import models_v2
import neutron.ipam as ipam
from neutron.ipam import driver
from neutron.openstack.common import uuidutils


class SubnetAllocator(driver.Pool):
    """Class for handling allocation of subnet prefixes from a subnet pool.

       This class leverages the pluggable IPAM interface where possible to
       make merging into IPAM framework easier in future cycles.
    """

    def __init__(self, subnetpool):
        self._subnetpool = subnetpool
        self._sp_helper = SubnetPoolHelper()

    def _lock_subnetpool(self, session):
        """Lock subnetpool associated row.

        This method disallows to allocate concurrently 2 subnets in the same
        subnetpool, it's required to ensure non-overlapping cidrs in the same
        subnetpool.
        """
        # FIXME(cbrandily): not working with Galera
        (session.query(models_v2.SubnetPool.id).
         filter_by(id=self._subnetpool['id']).
         with_lockmode('update').first())

    def _get_allocated_cidrs(self, session):
        query = session.query(models_v2.Subnet)
        subnets = query.filter_by(subnetpool_id=self._subnetpool['id'])
        return (x.cidr for x in subnets)

    def _get_available_prefix_list(self, session):
        prefixes = (x.cidr for x in self._subnetpool.prefixes)
        allocations = self._get_allocated_cidrs(session)
        prefix_set = netaddr.IPSet(iterable=prefixes)
        allocation_set = netaddr.IPSet(iterable=allocations)
        available_set = prefix_set.difference(allocation_set)
        available_set.compact()
        return sorted(available_set.iter_cidrs(),
                      key=operator.attrgetter('prefixlen'),
                      reverse=True)

    def _num_quota_units_in_prefixlen(self, prefixlen, quota_unit):
        return math.pow(2, quota_unit - prefixlen)

    def _allocations_used_by_tenant(self, session, quota_unit):
        subnetpool_id = self._subnetpool['id']
        tenant_id = self._subnetpool['tenant_id']
        with session.begin(subtransactions=True):
            qry = session.query(models_v2.Subnet)
            allocations = qry.filter_by(subnetpool_id=subnetpool_id,
                                        tenant_id=tenant_id)
            value = 0
            for allocation in allocations:
                prefixlen = netaddr.IPNetwork(allocation.cidr).prefixlen
                value += self._num_quota_units_in_prefixlen(prefixlen,
                                                            quota_unit)
            return value

    def _check_subnetpool_tenant_quota(self, session, tenant_id, prefixlen):
        quota_unit = self._sp_helper.ip_version_subnetpool_quota_unit(
                                               self._subnetpool['ip_version'])
        quota = self._subnetpool.get('default_quota')

        if quota:
            used = self._allocations_used_by_tenant(session, quota_unit)
            requested_units = self._num_quota_units_in_prefixlen(prefixlen,
                                                                 quota_unit)

            if used + requested_units > quota:
                raise n_exc.SubnetPoolQuotaExceeded()

    def _allocate_any_subnet(self, session, request):
        with session.begin(subtransactions=True):
            self._lock_subnetpool(session)
            self._check_subnetpool_tenant_quota(session,
                                                request.tenant_id,
                                                request.prefixlen)
            prefix_pool = self._get_available_prefix_list(session)
            for prefix in prefix_pool:
                if request.prefixlen >= prefix.prefixlen:
                    subnet = prefix.subnet(request.prefixlen).next()
                    gateway_ip = request.gateway_ip
                    if not gateway_ip:
                        gateway_ip = subnet.network + 1

                    return IpamSubnet(request.tenant_id,
                                      request.subnet_id,
                                      subnet.cidr,
                                      gateway_ip=gateway_ip,
                                      allocation_pools=None)
            msg = _("Insufficient prefix space to allocate subnet size /%s")
            raise n_exc.SubnetAllocationError(reason=msg %
                                              str(request.prefixlen))

    def _allocate_specific_subnet(self, session, request):
        with session.begin(subtransactions=True):
            self._lock_subnetpool(session)
            self._check_subnetpool_tenant_quota(session,
                                                request.tenant_id,
                                                request.prefixlen)
            subnet = request.subnet
            available = self._get_available_prefix_list(session)
            matched = netaddr.all_matching_cidrs(subnet, available)
            if len(matched) is 1 and matched[0].prefixlen <= subnet.prefixlen:
                return IpamSubnet(request.tenant_id,
                                  request.subnet_id,
                                  subnet.cidr,
                                  gateway_ip=request.gateway_ip,
                                  allocation_pools=request.allocation_pools)
            msg = _("Cannot allocate requested subnet from the available "
                    "set of prefixes")
            raise n_exc.SubnetAllocationError(reason=msg)

    def allocate_subnet(self, session, request):
        max_prefixlen = int(self._subnetpool['max_prefixlen'])
        min_prefixlen = int(self._subnetpool['min_prefixlen'])
        if request.prefixlen > max_prefixlen:
            raise n_exc.MaxPrefixSubnetAllocationError(
                              prefixlen=request.prefixlen,
                              max_prefixlen=max_prefixlen)
        if request.prefixlen < min_prefixlen:
            raise n_exc.MinPrefixSubnetAllocationError(
                              prefixlen=request.prefixlen,
                              min_prefixlen=min_prefixlen)

        if isinstance(request, ipam.AnySubnetRequest):
            return self._allocate_any_subnet(session, request)
        elif isinstance(request, ipam.SpecificSubnetRequest):
            return self._allocate_specific_subnet(session, request)
        else:
            msg = _("Unsupported request type")
            raise n_exc.SubnetAllocationError(reason=msg)

    def get_subnet(self, subnet, subnet_id):
        raise NotImplementedError()

    def update_subnet(self, request):
        raise NotImplementedError()

    def remove_subnet(self, subnet, subnet_id):
        raise NotImplementedError()


class IpamSubnet(driver.Subnet):

    def __init__(self,
                 tenant_id,
                 subnet_id,
                 cidr,
                 gateway_ip=None,
                 allocation_pools=None):
        self._req = ipam.SpecificSubnetRequest(tenant_id,
                                               subnet_id,
                                               cidr,
                                               gateway_ip=gateway_ip,
                                               allocation_pools=None)

    def allocate(self, address_request):
        raise NotImplementedError()

    def deallocate(self, address):
        raise NotImplementedError()

    def get_details(self):
        return self._req


class SubnetPoolReader(object):
    '''Class to assist with reading a subnetpool, loading defaults, and
       inferring IP version from prefix list. Provides a common way of
       reading a stored model or a create request with defaultable attributes.
    '''
    MIN_PREFIX_TYPE = 'min'
    MAX_PREFIX_TYPE = 'max'
    DEFAULT_PREFIX_TYPE = 'default'

    _sp_helper = None

    def __init__(self, subnetpool):
        self._read_prefix_info(subnetpool)
        self._sp_helper = SubnetPoolHelper()
        self._read_id(subnetpool)
        self._read_prefix_bounds(subnetpool)
        self._read_attrs(subnetpool,
                         ['tenant_id', 'name', 'shared'])
        self.subnetpool = {'id': self.id,
                           'name': self.name,
                           'tenant_id': self.tenant_id,
                           'prefixes': self.prefixes,
                           'min_prefix': self.min_prefix,
                           'min_prefixlen': self.min_prefixlen,
                           'max_prefix': self.max_prefix,
                           'max_prefixlen': self.max_prefixlen,
                           'default_prefix': self.default_prefix,
                           'default_prefixlen': self.default_prefixlen,
                           'default_quota': self.default_quota,
                           'shared': self.shared}

    def _read_attrs(self, subnetpool, keys):
        for key in keys:
            setattr(self, key, subnetpool[key])

    def _ip_version_from_cidr(self, cidr):
        return netaddr.IPNetwork(cidr).version

    def _prefixlen_from_cidr(self, cidr):
        return netaddr.IPNetwork(cidr).prefixlen

    def _read_id(self, subnetpool):
        id = subnetpool.get('id', attributes.ATTR_NOT_SPECIFIED)
        if id is attributes.ATTR_NOT_SPECIFIED:
            id = uuidutils.generate_uuid()
        self.id = id

    def _read_prefix_bounds(self, subnetpool):
        ip_version = self.ip_version
        default_min = self._sp_helper.default_min_prefixlen(ip_version)
        default_max = self._sp_helper.default_max_prefixlen(ip_version)

        self._read_prefix_bound(self.MIN_PREFIX_TYPE,
                                subnetpool,
                                default_min)
        self._read_prefix_bound(self.MAX_PREFIX_TYPE,
                                subnetpool,
                                default_max)
        self._read_prefix_bound(self.DEFAULT_PREFIX_TYPE,
                                subnetpool,
                                self.min_prefixlen)

        self._sp_helper.validate_min_prefixlen(self.min_prefixlen,
                                               self.max_prefixlen)
        self._sp_helper.validate_max_prefixlen(self.max_prefixlen,
                                               ip_version)
        self._sp_helper.validate_default_prefixlen(self.min_prefixlen,
                                                self.max_prefixlen,
                                                self.default_prefixlen)

    def _read_prefix_bound(self, type, subnetpool, default_bound=None):
        prefixlen_attr = type + '_prefixlen'
        prefix_attr = type + '_prefix'
        prefixlen = subnetpool.get(prefixlen_attr,
                                   attributes.ATTR_NOT_SPECIFIED)
        wildcard = self._sp_helper.wildcard(self.ip_version)

        if prefixlen is attributes.ATTR_NOT_SPECIFIED and default_bound:
            prefixlen = default_bound

        if prefixlen is not attributes.ATTR_NOT_SPECIFIED:
            prefix_cidr = '/'.join((wildcard,
                                    str(prefixlen)))
            setattr(self, prefix_attr, prefix_cidr)
            setattr(self, prefixlen_attr, prefixlen)

    def _read_prefix_info(self, subnetpool):
        prefix_list = subnetpool['prefixes']
        if not prefix_list:
            raise n_exc.EmptySubnetPoolPrefixList()

        ip_version = None
        for prefix in prefix_list:
            if not ip_version:
                ip_version = netaddr.IPNetwork(prefix).version
            elif netaddr.IPNetwork(prefix).version != ip_version:
                raise n_exc.PrefixVersionMismatch()
        self.default_quota = subnetpool.get('default_quota')

        if self.default_quota is attributes.ATTR_NOT_SPECIFIED:
            self.default_quota = None

        self.ip_version = ip_version
        self.prefixes = self._compact_subnetpool_prefix_list(prefix_list)

    def _compact_subnetpool_prefix_list(self, prefix_list):
        """Compact any overlapping prefixes in prefix_list and return the
           result
        """
        ip_set = netaddr.IPSet()
        for prefix in prefix_list:
            ip_set.add(netaddr.IPNetwork(prefix))
        ip_set.compact()
        return [str(x.cidr) for x in ip_set.iter_cidrs()]


class SubnetPoolHelper(object):

    _PREFIX_VERSION_INFO = {4: {'max_prefixlen': constants.IPv4_BITS,
                               'wildcard': '0.0.0.0',
                               'default_min_prefixlen': 8,
                               # IPv4 quota measured in units of /32
                               'quota_units': 32},
                           6: {'max_prefixlen': constants.IPv6_BITS,
                               'wildcard': '::',
                               'default_min_prefixlen': 64,
                               # IPv6 quota measured in units of /64
                               'quota_units': 64}}

    def validate_min_prefixlen(self, min_prefixlen, max_prefixlen):
        if min_prefixlen < 0:
            raise n_exc.UnsupportedMinSubnetPoolPrefix(prefix=min_prefixlen,
                                                       version=4)
        if min_prefixlen > max_prefixlen:
            raise n_exc.IllegalSubnetPoolPrefixBounds(
                                             prefix_type='min_prefixlen',
                                             prefixlen=min_prefixlen,
                                             base_prefix_type='max_prefixlen',
                                             base_prefixlen=max_prefixlen)

    def validate_max_prefixlen(self, prefixlen, ip_version):
        max = self._PREFIX_VERSION_INFO[ip_version]['max_prefixlen']
        if prefixlen > max:
            raise n_exc.IllegalSubnetPoolPrefixBounds(
                                            prefix_type='max_prefixlen',
                                            prefixlen=prefixlen,
                                            base_prefix_type='ip_version_max',
                                            base_prefixlen=max)

    def validate_default_prefixlen(self,
                                   min_prefixlen,
                                   max_prefixlen,
                                   default_prefixlen):
        if default_prefixlen < min_prefixlen:
            raise n_exc.IllegalSubnetPoolPrefixBounds(
                                             prefix_type='default_prefixlen',
                                             prefixlen=default_prefixlen,
                                             base_prefix_type='min_prefixlen',
                                             base_prefixlen=min_prefixlen)
        if default_prefixlen > max_prefixlen:
            raise n_exc.IllegalSubnetPoolPrefixBounds(
                                             prefix_type='default_prefixlen',
                                             prefixlen=default_prefixlen,
                                             base_prefix_type='max_prefixlen',
                                             base_prefixlen=max_prefixlen)

    def wildcard(self, ip_version):
        return self._PREFIX_VERSION_INFO[ip_version]['wildcard']

    def default_max_prefixlen(self, ip_version):
        return self._PREFIX_VERSION_INFO[ip_version]['max_prefixlen']

    def default_min_prefixlen(self, ip_version):
        return self._PREFIX_VERSION_INFO[ip_version]['default_min_prefixlen']

    def ip_version_subnetpool_quota_unit(self, ip_version):
        return self._PREFIX_VERSION_INFO[ip_version]['quota_units']
