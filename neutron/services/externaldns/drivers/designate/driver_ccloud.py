# Copyright (c) 2016 IBM
# Copyright 2025 SAP SE
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


from designateclient import exceptions as d_exc
from designateclient.v2 import client as d_client
from keystoneauth1 import loading
from keystoneauth1 import token_endpoint
import netaddr
from neutron_lib import constants
from neutron_lib.exceptions import dns as dns_exc
from oslo_config import cfg
from oslo_log import log

from neutron.conf.services import extdns_designate_driver
from neutron.services.externaldns import driver

IPV4_PTR_ZONE_PREFIX_MIN_SIZE = 8
IPV4_PTR_ZONE_PREFIX_MAX_SIZE = 24
IPV6_PTR_ZONE_PREFIX_MIN_SIZE = 4
IPV6_PTR_ZONE_PREFIX_MAX_SIZE = 124

_SESSION = None

CONF = cfg.CONF
extdns_designate_driver.register_designate_opts()

LOG = log.getLogger(__name__)


def get_clients(context, all_projects=False, edit_managed=False):
    global _SESSION

    if not _SESSION:
        _SESSION = loading.load_session_from_conf_options(
            CONF, 'designate')

    auth = token_endpoint.Token(CONF.designate.url, context.auth_token)
    client = d_client.Client(session=_SESSION, auth=auth)
    admin_auth = loading.load_auth_from_conf_options(CONF, 'designate')
    admin_client = d_client.Client(session=_SESSION, auth=admin_auth,
                                   endpoint_override=CONF.designate.url,
                                   all_projects=all_projects,
                                   edit_managed=edit_managed)
    return client, admin_client


def get_all_projects_client(context):
    auth = token_endpoint.Token(CONF.designate.url, context.auth_token)
    return d_client.Client(session=_SESSION, auth=auth, all_projects=True)


def get_all_projects_edit_managed_client(context):
    return get_clients(context, all_projects=True, edit_managed=True)


class DesignateCcloud(driver.ExternalDNSService):
    """Driver for Designate."""

    def __init__(self):
        super().__init__()
        ipv4_ptr_zone_size = CONF.designate.ipv4_ptr_zone_prefix_size
        ipv6_ptr_zone_size = CONF.designate.ipv6_ptr_zone_prefix_size

        if (ipv4_ptr_zone_size < IPV4_PTR_ZONE_PREFIX_MIN_SIZE or
                ipv4_ptr_zone_size > IPV4_PTR_ZONE_PREFIX_MAX_SIZE or
                (ipv4_ptr_zone_size % 8) != 0):
            raise dns_exc.InvalidPTRZoneConfiguration(
                parameter='ipv4_ptr_zone_size', number='8',
                maximum=str(IPV4_PTR_ZONE_PREFIX_MAX_SIZE),
                minimum=str(IPV4_PTR_ZONE_PREFIX_MIN_SIZE))

        if (ipv6_ptr_zone_size < IPV6_PTR_ZONE_PREFIX_MIN_SIZE or
                ipv6_ptr_zone_size > IPV6_PTR_ZONE_PREFIX_MAX_SIZE or
                (ipv6_ptr_zone_size % 4) != 0):
            raise dns_exc.InvalidPTRZoneConfiguration(
                parameter='ipv6_ptr_zone_size', number='4',
                maximum=str(IPV6_PTR_ZONE_PREFIX_MAX_SIZE),
                minimum=str(IPV6_PTR_ZONE_PREFIX_MIN_SIZE))

    def create_record_set(self, context, dns_domain, dns_name, records,
                          fip_id=None):
        """Create a record set in the specified zone.

        :param context: neutron api request context
        :type context: neutron_lib.context.Context
        :param dns_domain: the dns_domain where the record set will be created
        :type dns_domain: String
        :param dns_name: the name associated with the record set
        :type dns_name: String
        :param records: the records in the set
        :type records: List of Strings
        :param fip_id: Floating IP id
        :type fip_id: String
        :raises: neutron.extensions.dns.DNSDomainNotFound
                 neutron.extensions.dns.DuplicateRecordSet
        """
        designate, designate_admin = get_clients(context)
        v4, v6 = self._classify_records(records)
        try:
            if v4:
                designate.recordsets.create(dns_domain, dns_name, 'A', v4)
            if v6:
                designate.recordsets.create(dns_domain, dns_name, 'AAAA', v6)
        except d_exc.NotFound:
            raise dns_exc.DNSDomainNotFound(dns_domain=dns_domain)
        except d_exc.Conflict:
            fqdn = ".".join([dns_name, dns_domain])
            if v4:
                designate.recordsets.update(dns_domain, fqdn, {"records": v4})
            if v6:
                designate.recordsets.update(dns_domain, fqdn, {"records": v6})
        except d_exc.OverQuota:
            raise dns_exc.ExternalDNSOverQuota(resource="recordset")

        if not CONF.designate.allow_reverse_dns_lookup:
            return
        # Set up the PTR records
        if fip_id:
            designate.floatingips.set(
                f"{CONF.designate.region_name}:{fip_id}",
                f"{dns_name}.{dns_domain}"
            )
        else:
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
                except d_exc.Conflict:
                    # It can happen that we have left
                    # -over or manually created PTR
                    # from before (e.g. by a project that was using same FIP).
                    # If PTR exists, update it even if it is 'managed'.
                    c_designate, c_designate_admin = get_clients(
                        context,
                        edit_managed=True
                    )
                    recordset_dict = {'records': [recordset_name]}
                    # Use own instance of admin client as a precaution
                    c_designate_admin.recordsets.update(in_addr_zone_name,
                                                        in_addr_name,
                                                        recordset_dict)
                except d_exc.NotFound:
                    # Note(jh): If multiple PTRs get created at the same time,
                    # the creation of the zone may fail with a conflict because
                    # it has already been created by a parallel job. So we
                    # ignore that error and try to create the recordset
                    # anyway. That call will still fail in the end if something
                    # is really broken. See bug 1891309.
                    try:
                        designate_admin.zones.create(
                            in_addr_zone_name, email=ptr_zone_email,
                            description=in_addr_zone_description)
                    except d_exc.Conflict:
                        LOG.debug('Conflict when trying to create PTR zone %s,'
                                  ' assuming it exists.',
                                  in_addr_zone_name)
                        pass
                    except d_exc.OverQuota:
                        raise dns_exc.ExternalDNSOverQuota(resource='zone')
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
            return int((constants.IPv4_BITS -
                        CONF.designate.ipv4_ptr_zone_prefix_size) / 8)
        return int((constants.IPv6_BITS -
                    CONF.designate.ipv6_ptr_zone_prefix_size) / 4)

    def delete_record_set(self, context, dns_domain, dns_name, records):
        client, admin_client = get_clients(context)
        ids_to_delete = []
        try:
            # first try regular client:
            ids_to_delete = self._get_ids_ips_to_delete(
                dns_domain, '%s.%s' % (dns_name, dns_domain), records, client)
        except dns_exc.DNSDomainNotFound:
            # Try whether we have admin powers and can see all projects
            # and also handle managed records (to prevent leftover PTRs):
            client, admin_client = get_all_projects_edit_managed_client(
                context)
            try:
                ids_to_delete = self._get_ids_ips_to_delete(
                    dns_domain,
                    '%s.%s' % (dns_name, dns_domain),
                    records,
                    client)
            except dns_exc.DNSDomainNotFound:
                LOG.debug("The domain '%s' not found in Designate",
                          dns_domain)
        except d_exc.Forbidden:
            LOG.error("Cannot determine Designate record ids for "
                      "deletion of: '%(name)s.%(dom)s'",
                      {'name': dns_name, 'dom': dns_domain})

        for _id in ids_to_delete:
            try:
                client.recordsets.delete(dns_domain, _id)
            except (d_exc.Forbidden, d_exc.NotFound) as exc:
                LOG.error("Cannot delete Designate record with id %(recid)s in"
                          " domain: %(dom)s. Error: %(err)s",
                          {'recid': _id, 'dom': dns_domain, 'err': exc})

        if not CONF.designate.allow_reverse_dns_lookup:
            return

        # PTR records part
        client, admin_client = get_all_projects_edit_managed_client(
            context)
        for record in records:
            in_addr_name = netaddr.IPAddress(record).reverse_dns
            in_addr_zone_name = self._get_in_addr_zone_name(in_addr_name)
            try:
                admin_client.recordsets.delete(in_addr_zone_name,
                                               in_addr_name)
            except (dns_exc.DNSDomainNotFound, d_exc.NotFound):
                LOG.debug("No '%s' PTR record was found in Designate.",
                          in_addr_name)
            except d_exc.Forbidden:
                LOG.error("Cannot delete '%s' PTR record.",
                          in_addr_name)

    def _get_ids_ips_to_delete(self, dns_domain, name, records,
                               designate_client):
        try:
            recordsets = designate_client.recordsets.list(
                dns_domain, criterion={"name": "%s" % name})
        except (d_exc.NotFound, d_exc.Forbidden):
            raise dns_exc.DNSDomainNotFound(dns_domain=dns_domain)
        ids = [rec['id'] for rec in recordsets]
        ips = [str(ip) for rec in recordsets for ip in rec['records']]
        if set(ips) != set(records):
            raise dns_exc.DuplicateRecordSet(dns_name=name)
        return ids
