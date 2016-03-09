# Copyright (c) 2016 IBM
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

from designateclient import exceptions as d_exc
from designateclient.v2 import client as d_client
from keystoneclient.auth.identity.generic import password
from keystoneclient.auth import token_endpoint
from keystoneclient import session
from oslo_config import cfg
from oslo_log import log

from neutron._i18n import _
from neutron.extensions import dns
from neutron.services.externaldns import driver

IPV4_PTR_ZONE_PREFIX_MIN_SIZE = 8
IPV4_PTR_ZONE_PREFIX_MAX_SIZE = 24
IPV6_PTR_ZONE_PREFIX_MIN_SIZE = 4
IPV6_PTR_ZONE_PREFIX_MAX_SIZE = 124

LOG = log.getLogger(__name__)
_SESSION = None

designate_opts = [
    cfg.StrOpt('url',
               help=_('URL for connecting to designate')),
    cfg.StrOpt('admin_username',
               help=_('Username for connecting to designate in admin '
                      'context')),
    cfg.StrOpt('admin_password',
               help=_('Password for connecting to designate in admin '
                      'context'),
               secret=True),
    cfg.StrOpt('admin_tenant_id',
               help=_('Tenant id for connecting to designate in admin '
                      'context')),
    cfg.StrOpt('admin_tenant_name',
               help=_('Tenant name for connecting to designate in admin '
                      'context')),
    cfg.StrOpt('admin_auth_url',
               help=_('Authorization URL for connecting to designate in admin '
                      'context')),
    cfg.BoolOpt('allow_reverse_dns_lookup', default=True,
                help=_('Allow the creation of PTR records')),
    cfg.IntOpt('ipv4_ptr_zone_prefix_size', default=24,
        help=_('Number of bits in an ipv4 PTR zone that will be considered '
               'network prefix. It has to align to byte boundary. Minimum '
               'value is 8. Maximum value is 24. As a consequence, range '
               'of values is 8, 16 and 24')),
    cfg.IntOpt('ipv6_ptr_zone_prefix_size', default=120,
        help=_('Number of bits in an ipv6 PTR zone that will be considered '
               'network prefix. It has to align to nyble boundary. Minimum '
               'value is 4. Maximum value is 124. As a consequence, range '
               'of values is 4, 8, 12, 16,..., 124')),
    cfg.StrOpt('ptr_zone_email', default='',
               help=_('The email address to be used when creating PTR zones. '
                      'If not specified, the email address will be '
                      'admin@<dns_domain>')),
]

DESIGNATE_GROUP = 'designate'

CONF = cfg.CONF
CONF.register_opts(designate_opts, DESIGNATE_GROUP)


def get_clients(context):
    global _SESSION

    if not _SESSION:
        _SESSION = session.Session()

    auth = token_endpoint.Token(CONF.designate.url, context.auth_token)
    client = d_client.Client(session=_SESSION, auth=auth)
    admin_auth = password.Password(
        auth_url=CONF.designate.admin_auth_url,
        username=CONF.designate.admin_username,
        password=CONF.designate.admin_password,
        tenant_name=CONF.designate.admin_tenant_name,
        tenant_id=CONF.designate.admin_tenant_id)
    admin_client = d_client.Client(session=_SESSION, auth=admin_auth)
    return client, admin_client


class Designate(driver.ExternalDNSService):
    """Driver for Designate."""

    def __init__(self):
        ipv4_ptr_zone_size = CONF.designate.ipv4_ptr_zone_prefix_size
        ipv6_ptr_zone_size = CONF.designate.ipv6_ptr_zone_prefix_size

        if (ipv4_ptr_zone_size < IPV4_PTR_ZONE_PREFIX_MIN_SIZE or
            ipv4_ptr_zone_size > IPV4_PTR_ZONE_PREFIX_MAX_SIZE or
            (ipv4_ptr_zone_size % 8) != 0):
            raise dns.InvalidPTRZoneConfiguration(
                parameter='ipv4_ptr_zone_size', number='8',
                maximum=str(IPV4_PTR_ZONE_PREFIX_MAX_SIZE),
                minimum=str(IPV4_PTR_ZONE_PREFIX_MIN_SIZE))

        if (ipv6_ptr_zone_size < IPV6_PTR_ZONE_PREFIX_MIN_SIZE or
            ipv6_ptr_zone_size > IPV6_PTR_ZONE_PREFIX_MAX_SIZE or
            (ipv6_ptr_zone_size % 4) != 0):
            raise dns.InvalidPTRZoneConfiguration(
                parameter='ipv6_ptr_zone_size', number='4',
                maximum=str(IPV6_PTR_ZONE_PREFIX_MAX_SIZE),
                minimum=str(IPV6_PTR_ZONE_PREFIX_MIN_SIZE))

    def create_record_set(self, context, dns_domain, dns_name, records):
        designate, designate_admin = get_clients(context)
        v4, v6 = self._classify_records(records)
        try:
            if v4:
                designate.recordsets.create(dns_domain, dns_name, 'A', v4)
            if v6:
                designate.recordsets.create(dns_domain, dns_name, 'AAAA', v6)
        except d_exc.NotFound:
            raise dns.DNSDomainNotFound(dns_domain=dns_domain)
        except d_exc.Conflict:
            raise dns.DuplicateRecordSet(dns_name=dns_name)

        if not CONF.designate.allow_reverse_dns_lookup:
            return
        # Set up the PTR records
        recordset_name = '%s.%s' % (dns_name, dns_domain)
        ptr_zone_email = 'admin@%s' % dns_domain[:-1]
        if CONF.designate.ptr_zone_email:
            ptr_zone_email = CONF.designate.ptr_zone_email
        for record in records:
            in_addr_name = netaddr.IPAddress(record).reverse_dns
            in_addr_zone_name = self._get_in_addr_zone_name(in_addr_name)
            in_addr_zone_description = (
                'An %s zone for reverse lookups set up by Neutron.' %
                '.'.join(in_addr_name.split('.')[-3:]))
            try:
                # Since we don't delete in-addr zones, assume it already
                # exists. If it doesn't, create it
                designate_admin.recordsets.create(in_addr_zone_name,
                                                  in_addr_name, 'PTR',
                                                  [recordset_name])
            except d_exc.NotFound:
                designate_admin.zones.create(
                    in_addr_zone_name, email=ptr_zone_email,
                    description=in_addr_zone_description)
                designate_admin.recordsets.create(in_addr_zone_name,
                                                  in_addr_name, 'PTR',
                                                  [recordset_name])

    def _classify_records(self, records):
        v4 = []
        v6 = []
        for record in records:
            if netaddr.IPAddress(record).version == 4:
                v4.append(record)
            else:
                v6.append(record)
        return v4, v6

    def _get_in_addr_zone_name(self, in_addr_name):
        units = self._get_bytes_or_nybles_to_skip(in_addr_name)
        return '.'.join(in_addr_name.split('.')[units:])

    def _get_bytes_or_nybles_to_skip(self, in_addr_name):
        if 'in-addr.arpa' in in_addr_name:
            return int((32 - CONF.designate.ipv4_ptr_zone_prefix_size) / 8)
        return int((128 - CONF.designate.ipv6_ptr_zone_prefix_size) / 4)

    def delete_record_set(self, context, dns_domain, dns_name, records):
        designate, designate_admin = get_clients(context)
        ids_to_delete = self._get_ids_ips_to_delete(
            dns_domain, '%s.%s' % (dns_name, dns_domain), records, designate)
        for _id in ids_to_delete:
            designate.recordsets.delete(dns_domain, _id)
        if not CONF.designate.allow_reverse_dns_lookup:
            return

        for record in records:
            in_addr_name = netaddr.IPAddress(record).reverse_dns
            in_addr_zone_name = self._get_in_addr_zone_name(in_addr_name)
            designate_admin.recordsets.delete(in_addr_zone_name, in_addr_name)

    def _get_ids_ips_to_delete(self, dns_domain, name, records,
                               designate_client):
        try:
            recordsets = designate_client.recordsets.list(
                dns_domain, criterion={"name": "%s" % name})
        except d_exc.NotFound:
            raise dns.DNSDomainNotFound(dns_domain=dns_domain)
        ids = [rec['id'] for rec in recordsets]
        ips = [ip for rec in recordsets for ip in rec['records']]
        if set(ips) != set(records):
            raise dns.DuplicateRecordSet(dns_name=name)
        return ids
