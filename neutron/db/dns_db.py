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

from neutron_lib.api.definitions import dns as dns_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.api import extensions
from neutron_lib.api import validators
from neutron_lib.db import resource_extend
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import dns as dns_exc
from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _
from neutron.objects import floatingip as fip_obj
from neutron.objects import network
from neutron.objects import ports as port_obj
from neutron.services.externaldns import driver

LOG = logging.getLogger(__name__)


class DNSActionsData:

    def __init__(self, current_dns_name=None, current_dns_domain=None,
                 previous_dns_name=None, previous_dns_domain=None):
        self.current_dns_name = current_dns_name
        self.current_dns_domain = current_dns_domain
        self.previous_dns_name = previous_dns_name
        self.previous_dns_domain = previous_dns_domain


@resource_extend.has_resource_extenders
class DNSDbMixin:
    """Mixin class to add DNS methods to db_base_plugin_v2."""

    _dns_driver = None

    @property
    def dns_driver(self):
        if self._dns_driver:
            return self._dns_driver
        if not cfg.CONF.external_dns_driver:
            return
        try:
            self._dns_driver = driver.ExternalDNSService.get_instance()
            LOG.debug("External DNS driver loaded: %s",
                      cfg.CONF.external_dns_driver)
            return self._dns_driver
        except ImportError:
            LOG.exception("ImportError exception occurred while loading "
                          "the external DNS service driver")
            raise dns_exc.ExternalDNSDriverNotFound(
                driver=cfg.CONF.external_dns_driver)

    @staticmethod
    @resource_extend.extends([l3_apidef.FLOATINGIPS])
    def _extend_floatingip_dict_dns(floatingip_res, floatingip_db):
        floatingip_res['dns_domain'] = ''
        floatingip_res['dns_name'] = ''
        if floatingip_db.dns:
            floatingip_res['dns_domain'] = floatingip_db.dns['dns_domain']
            floatingip_res['dns_name'] = floatingip_db.dns['dns_name']
        return floatingip_res

    def _process_dns_floatingip_create_precommit(self, context,
                                                 floatingip_data, req_data):
        # expects to be called within a plugin's session
        dns_domain = req_data.get(dns_apidef.DNSDOMAIN)
        if not validators.is_attr_set(dns_domain):
            return
        if not self.dns_driver:
            return

        dns_name = req_data[dns_apidef.DNSNAME]
        self._validate_floatingip_dns(dns_name, dns_domain)

        current_dns_name, current_dns_domain = (
            self._get_requested_state_for_external_dns_service_create(
                context, floatingip_data, req_data))
        dns_actions_data = None
        if current_dns_name and current_dns_domain:
            fip_obj.FloatingIPDNS(
                context,
                floatingip_id=floatingip_data['id'],
                dns_name=req_data[dns_apidef.DNSNAME],
                dns_domain=req_data[dns_apidef.DNSDOMAIN],
                published_dns_name=current_dns_name,
                published_dns_domain=current_dns_domain).create()
            dns_actions_data = DNSActionsData(
                current_dns_name=current_dns_name,
                current_dns_domain=current_dns_domain)
        floatingip_data['dns_name'] = dns_name
        floatingip_data['dns_domain'] = dns_domain
        return dns_actions_data

    def _process_dns_floatingip_create_postcommit(self, context,
                                                  floatingip_data,
                                                  dns_actions_data):
        if not dns_actions_data:
            return
        self._add_ips_to_external_dns_service(
            context, dns_actions_data.current_dns_domain,
            dns_actions_data.current_dns_name,
            [floatingip_data['floating_ip_address']])

    def _process_dns_floatingip_update_precommit(self, context,
                                                 floatingip_data):
        # expects to be called within a plugin's session
        if not extensions.is_extension_supported(
                self._core_plugin, dns_apidef.ALIAS):
            return
        if not self.dns_driver:
            return
        dns_data_db = fip_obj.FloatingIPDNS.get_object(
            context, floatingip_id=floatingip_data['id'])
        if dns_data_db and dns_data_db['dns_name']:
            # dns_name and dns_domain assigned for floating ip. It doesn't
            # matter whether they are defined for internal port
            return
        current_dns_name, current_dns_domain = (
            self._get_requested_state_for_external_dns_service_update(
                context, floatingip_data))
        if dns_data_db:
            if (dns_data_db['published_dns_name'] == current_dns_name and
                    dns_data_db['published_dns_domain'] == current_dns_domain):
                return
            dns_actions_data = DNSActionsData(
                previous_dns_name=dns_data_db['published_dns_name'],
                previous_dns_domain=dns_data_db['published_dns_domain'])
            if current_dns_name and current_dns_domain:
                dns_data_db['published_dns_name'] = current_dns_name
                dns_data_db['published_dns_domain'] = current_dns_domain
                dns_actions_data.current_dns_name = current_dns_name
                dns_actions_data.current_dns_domain = current_dns_domain
            else:
                dns_data_db.delete()
            return dns_actions_data
        if current_dns_name and current_dns_domain:
            fip_obj.FloatingIPDNS(
                context,
                floatingip_id=floatingip_data['id'],
                dns_name='',
                dns_domain='',
                published_dns_name=current_dns_name,
                published_dns_domain=current_dns_domain).create()
            return DNSActionsData(current_dns_name=current_dns_name,
                                  current_dns_domain=current_dns_domain)

    def _process_dns_floatingip_update_postcommit(self, context,
                                                  floatingip_data,
                                                  dns_actions_data):
        if not dns_actions_data:
            return
        if dns_actions_data.previous_dns_name:
            self._delete_floatingip_from_external_dns_service(
                context, dns_actions_data.previous_dns_domain,
                dns_actions_data.previous_dns_name,
                [floatingip_data['floating_ip_address']])
        if dns_actions_data.current_dns_name:
            self._add_ips_to_external_dns_service(
                context, dns_actions_data.current_dns_domain,
                dns_actions_data.current_dns_name,
                [floatingip_data['floating_ip_address']])

    def _process_dns_floatingip_delete(self, context, floatingip_data):
        if not extensions.is_extension_supported(
                self._core_plugin, dns_apidef.ALIAS):
            return
        dns_data_db = fip_obj.FloatingIPDNS.get_object(
            context, floatingip_id=floatingip_data['id'])
        if dns_data_db:
            self._delete_floatingip_from_external_dns_service(
                context, dns_data_db['published_dns_domain'],
                dns_data_db['published_dns_name'],
                [floatingip_data['floating_ip_address']])

    def _validate_floatingip_dns(self, dns_name, dns_domain):
        if dns_domain and not dns_name:
            msg = _("dns_domain cannot be specified without a dns_name")
            raise n_exc.BadRequest(resource='floatingip', msg=msg)
        if dns_name and not dns_domain:
            msg = _("dns_name cannot be specified without a dns_domain")
            raise n_exc.BadRequest(resource='floatingip', msg=msg)

    def _get_internal_port_dns_data(self, context, floatingip_data):
        port_dns = port_obj.PortDNS.get_object(
            context, port_id=floatingip_data['port_id'])
        if not (port_dns and port_dns['dns_name']):
            return None, None
        net_dns = network.NetworkDNSDomain.get_net_dns_from_port(
            context=context, port_id=floatingip_data['port_id'])
        if not net_dns:
            return port_dns['dns_name'], None
        return port_dns['dns_name'], net_dns['dns_domain']

    def _delete_floatingip_from_external_dns_service(self, context, dns_domain,
                                                     dns_name, records):
        ips = [str(r) for r in records]
        try:
            self.dns_driver.delete_record_set(context, dns_domain, dns_name,
                                              ips)
        except dns_exc.DNSDomainNotFound:
            LOG.error("Error deleting Floating IP record %(name)s from "
                      "external DNS service. The DNS domain %(domain)s was "
                      "not found.",
                      {"name": dns_name,
                       "domain": dns_domain})
        except dns_exc.DuplicateRecordSet:
            LOG.error("Error deleting Floating IP record from external DNS "
                      "service. Duplicate Floating IP records for %(name)s in "
                      "domain %(domain)s were found.",
                      {"name": dns_name,
                       "domain": dns_domain})

    def _get_requested_state_for_external_dns_service_create(self, context,
                                                             floatingip_data,
                                                             req_data):
        fip_dns_name = req_data[dns_apidef.DNSNAME]
        if fip_dns_name:
            return fip_dns_name, req_data[dns_apidef.DNSDOMAIN]
        if floatingip_data['port_id']:
            return self._get_internal_port_dns_data(context, floatingip_data)
        return None, None

    def _get_requested_state_for_external_dns_service_update(self, context,
                                                             floatingip_data):
        if floatingip_data['port_id']:
            return self._get_internal_port_dns_data(context, floatingip_data)
        return None, None

    def _add_ips_to_external_dns_service(self, context, dns_domain, dns_name,
                                         records):
        ips = [str(r) for r in records]
        try:
            self.dns_driver.create_record_set(context, dns_domain, dns_name,
                                              ips)
        except dns_exc.DNSDomainNotFound:
            LOG.error("The DNS domain %(domain)s was not found. Creation of "
                      "Floating IP record %(name)s from external DNS service "
                      "will be skipped.",
                      {"name": dns_name,
                       "domain": dns_domain})
        except dns_exc.DuplicateRecordSet:
            LOG.error("A Floating IP record for %(name)s in domain %(domain)s "
                      "already exists. record creation in external DNS "
                      "service will be skipped.",
                      {"name": dns_name,
                       "domain": dns_domain})
