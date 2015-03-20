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

import netaddr
from neutron.api.v2 import attributes
from neutron.common import constants
from neutron.common import exceptions as n_exc
from neutron.openstack.common import uuidutils


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
        self._read_prefix_list(subnetpool)
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

    def _read_prefix_list(self, subnetpool):
        prefix_list = subnetpool['prefixes']
        if not prefix_list:
            raise n_exc.EmptySubnetPoolPrefixList()

        ip_version = None
        for prefix in prefix_list:
            if not ip_version:
                ip_version = netaddr.IPNetwork(prefix).version
            elif netaddr.IPNetwork(prefix).version != ip_version:
                raise n_exc.PrefixVersionMismatch()

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

    PREFIX_VERSION_INFO = {4: {'max_prefixlen': constants.IPv4_BITS,
                               'wildcard': '0.0.0.0',
                               'default_min_prefixlen': 8},
                           6: {'max_prefixlen': constants.IPv6_BITS,
                               'wildcard': '::',
                               'default_min_prefixlen': 64}}

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
        max = self.PREFIX_VERSION_INFO[ip_version]['max_prefixlen']
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
        return self.PREFIX_VERSION_INFO[ip_version]['wildcard']

    def default_max_prefixlen(self, ip_version):
        return self.PREFIX_VERSION_INFO[ip_version]['max_prefixlen']

    def default_min_prefixlen(self, ip_version):
        return self.PREFIX_VERSION_INFO[ip_version]['default_min_prefixlen']
