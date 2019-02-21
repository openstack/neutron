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
from neutron_lib.api.definitions import dns_domain_ports
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as lib_const
from neutron_lib.exceptions import dns as dns_exc
from neutron_lib.plugins import directory
from neutron_lib.plugins.ml2 import api
from neutron_lib.plugins import utils as plugin_utils
from oslo_config import cfg
from oslo_log import log as logging

from neutron.db import segments_db
from neutron.objects import network as net_obj
from neutron.objects import ports as port_obj
from neutron.services.externaldns import driver

LOG = logging.getLogger(__name__)


class DNSExtensionDriver(api.ExtensionDriver):
    _supported_extension_alias = dns_apidef.ALIAS

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_network(self, plugin_context, request_data, db_data):
        dns_domain = request_data.get(dns_apidef.DNSDOMAIN)
        if not validators.is_attr_set(dns_domain):
            return

        if dns_domain:
            net_obj.NetworkDNSDomain(plugin_context,
                                     network_id=db_data['id'],
                                     dns_domain=dns_domain).create()
        db_data[dns_apidef.DNSDOMAIN] = dns_domain

    def process_update_network(self, plugin_context, request_data, db_data):
        new_value = request_data.get(dns_apidef.DNSDOMAIN)
        if not validators.is_attr_set(new_value):
            return

        current_dns_domain = db_data.get(dns_apidef.DNSDOMAIN)
        if current_dns_domain == new_value:
            return

        net_id = db_data['id']
        if current_dns_domain:
            net_dns_domain = net_obj.NetworkDNSDomain.get_object(
                plugin_context,
                network_id=net_id)
            if new_value:
                net_dns_domain['dns_domain'] = new_value
                db_data[dns_apidef.DNSDOMAIN] = new_value
                net_dns_domain.update()
            else:
                net_dns_domain.delete()
                db_data[dns_apidef.DNSDOMAIN] = ''
        elif new_value:
            net_obj.NetworkDNSDomain(plugin_context,
                                     network_id=net_id,
                                     dns_domain=new_value).create()
            db_data[dns_apidef.DNSDOMAIN] = new_value

    def process_create_port(self, plugin_context, request_data, db_data):
        if not (request_data.get(dns_apidef.DNSNAME) or
                request_data.get(dns_apidef.DNSDOMAIN)):
            return
        dns_name, is_dns_domain_default = self._get_request_dns_name(
            request_data)
        if is_dns_domain_default:
            return
        network = self._get_network(plugin_context, db_data['network_id'])
        self._create_port_dns_record(plugin_context, request_data, db_data,
                                     network, dns_name)

    def _create_port_dns_record(self, plugin_context, request_data, db_data,
                                network, dns_name):
        external_dns_domain = (request_data.get(dns_apidef.DNSDOMAIN) or
                               network.get(dns_apidef.DNSDOMAIN))
        current_dns_name, current_dns_domain = (
            self._calculate_current_dns_name_and_domain(
                dns_name, external_dns_domain,
                self.external_dns_not_needed(plugin_context, network)))

        dns_data_obj = port_obj.PortDNS(
            plugin_context,
            port_id=db_data['id'],
            current_dns_name=current_dns_name,
            current_dns_domain=current_dns_domain,
            previous_dns_name='',
            previous_dns_domain='',
            dns_name=dns_name,
            dns_domain=request_data.get(dns_apidef.DNSDOMAIN, ''))
        dns_data_obj.create()
        return dns_data_obj

    def _calculate_current_dns_name_and_domain(self, dns_name,
                                               external_dns_domain,
                                               no_external_dns_service):
        # When creating a new PortDNS object, the current_dns_name and
        # current_dns_domain fields hold the data that the integration driver
        # will send to the external DNS service. They are set to non-blank
        # values only if all the following conditions are met:
        # 1) There is an external DNS integration driver configured
        # 2) The user request contains a valid non-blank value for the port's
        #    dns_name
        # 3) The user request contains a valid non-blank value for the port's
        #    dns_domain or the port's network has a non-blank value in its
        #    dns_domain attribute
        are_both_dns_attributes_set = dns_name and external_dns_domain
        if no_external_dns_service or not are_both_dns_attributes_set:
            return '', ''
        return dns_name, external_dns_domain

    def _update_dns_db(self, plugin_context, request_data, db_data, network):
        dns_name = request_data.get(dns_apidef.DNSNAME)
        dns_domain = request_data.get(dns_apidef.DNSDOMAIN)
        has_fixed_ips = 'fixed_ips' in request_data
        dns_data_db = port_obj.PortDNS.get_object(
            plugin_context,
            port_id=db_data['id'])
        if dns_data_db:
            is_dns_name_changed = (
                dns_name is not None and
                dns_data_db[dns_apidef.DNSNAME] != dns_name)
            is_dns_domain_changed = (
                dns_domain is not None and
                dns_data_db[dns_apidef.DNSDOMAIN] != dns_domain)
            if (is_dns_name_changed or is_dns_domain_changed or
                    (has_fixed_ips and dns_data_db['current_dns_name'])):
                dns_data_db = self._populate_previous_external_dns_data(
                    dns_data_db)
                dns_data_db = self._populate_current_external_dns_data(
                    request_data, network, dns_data_db, dns_name, dns_domain,
                    is_dns_name_changed, is_dns_domain_changed)
            elif not dns_data_db['current_dns_name']:
                # If port was removed from external DNS service in previous
                # update, make sure we don't attempt removal again
                dns_data_db['previous_dns_name'] = ''
                dns_data_db['previous_dns_domain'] = ''

            dns_data_db.update()
            return dns_data_db
        if dns_name or dns_domain:
            dns_data_db = self._create_port_dns_record(
                plugin_context, request_data, db_data, network, dns_name or '')
        return dns_data_db

    def _populate_previous_external_dns_data(self, dns_data_db):
        dns_data_db['previous_dns_name'] = (
            dns_data_db['current_dns_name'])
        dns_data_db['previous_dns_domain'] = (
            dns_data_db['current_dns_domain'])
        return dns_data_db

    def _populate_current_external_dns_data(self, request_data, network,
                                            dns_data_db, dns_name, dns_domain,
                                            is_dns_name_changed,
                                            is_dns_domain_changed):
        if is_dns_name_changed or is_dns_domain_changed:
            if is_dns_name_changed:
                dns_data_db[dns_apidef.DNSNAME] = dns_name
            external_dns_domain = (dns_data_db[dns_apidef.DNSDOMAIN] or
                                   network.get(dns_apidef.DNSDOMAIN))
            if is_dns_domain_changed:
                dns_data_db[dns_apidef.DNSDOMAIN] = dns_domain
                external_dns_domain = request_data[dns_apidef.DNSDOMAIN]
                if not external_dns_domain:
                    external_dns_domain = network.get(dns_apidef.DNSDOMAIN)
            dns_data_db['current_dns_name'] = dns_data_db[dns_apidef.DNSNAME]
            dns_data_db['current_dns_domain'] = external_dns_domain
            if not (dns_data_db['current_dns_name'] and
                    dns_data_db['current_dns_domain']):
                dns_data_db['current_dns_name'] = ''
                dns_data_db['current_dns_domain'] = ''
        return dns_data_db

    def process_update_port(self, plugin_context, request_data, db_data):
        has_dns_name = dns_apidef.DNSNAME in request_data
        has_fixed_ips = 'fixed_ips' in request_data
        has_dns_domain = dns_apidef.DNSDOMAIN in request_data
        if not any((has_dns_name, has_fixed_ips, has_dns_domain)):
            return
        is_dns_domain_default = self._get_request_dns_name(
            request_data)[1]
        if is_dns_domain_default:
            self._extend_port_dict(plugin_context.session, db_data,
                                   db_data, None)
            return
        network = self._get_network(plugin_context, db_data['network_id'])
        dns_data_db = None
        if self.external_dns_not_needed(plugin_context, network):
            # No need to update external DNS service. Only process the port's
            # dns_name or dns_domain attributes if necessary
            if has_dns_name or has_dns_domain:
                dns_data_db = self._process_only_port_update(
                    plugin_context, request_data, db_data)
        else:
            dns_data_db = self._update_dns_db(plugin_context, request_data,
                                              db_data, network)
        self._extend_port_dict(plugin_context.session, db_data, db_data,
                               dns_data_db)

    def _process_only_port_update(self, plugin_context, request_data,
                                  db_data):
        dns_name = request_data.get(dns_apidef.DNSNAME)
        dns_domain = request_data.get(dns_apidef.DNSDOMAIN)
        dns_data_db = port_obj.PortDNS.get_object(
            plugin_context,
            port_id=db_data['id'])
        if dns_data_db:
            if dns_name is not None and dns_data_db[
                    dns_apidef.DNSNAME] != dns_name:
                dns_data_db[dns_apidef.DNSNAME] = dns_name
            if (dns_domain is not None and
                    dns_data_db[dns_apidef.DNSDOMAIN] != dns_domain):
                dns_data_db[dns_apidef.DNSDOMAIN] = dns_domain
            dns_data_db.update()
            return dns_data_db
        dns_data_db = port_obj.PortDNS(plugin_context,
                                       port_id=db_data['id'],
                                       current_dns_name='',
                                       current_dns_domain='',
                                       previous_dns_name='',
                                       previous_dns_domain='',
                                       dns_name=dns_name or '',
                                       dns_domain=dns_domain or '')
        dns_data_db.create()
        return dns_data_db

    def external_dns_not_needed(self, context, network):
        """Decide if ports in network need to be sent to the DNS service.

        :param context: plugin request context
        :param network: network dictionary
        :return: True or False
        """
        pass

    def extend_network_dict(self, session, db_data, response_data):
        response_data[dns_apidef.DNSDOMAIN] = ''
        if db_data.dns_domain:
            response_data[dns_apidef.DNSDOMAIN] = db_data.dns_domain[
                dns_apidef.DNSDOMAIN]
        return response_data

    def _get_dns_domain(self):
        if not cfg.CONF.dns_domain:
            return ''
        if cfg.CONF.dns_domain.endswith('.'):
            return cfg.CONF.dns_domain
        return '%s.' % cfg.CONF.dns_domain

    def _get_request_dns_name(self, port):
        dns_domain = self._get_dns_domain()
        if dns_domain and dns_domain != lib_const.DNS_DOMAIN_DEFAULT:
            return port.get(dns_apidef.DNSNAME, ''), False
        return '', True

    def _get_request_dns_name_and_domain_name(self, dns_data_db):
        dns_domain = self._get_dns_domain()
        dns_name = ''
        if dns_domain and dns_domain != lib_const.DNS_DOMAIN_DEFAULT:
            if dns_data_db:
                dns_name = dns_data_db.dns_name
        return dns_name, dns_domain

    def _get_dns_names_for_port(self, ips, dns_data_db):
        dns_assignment = []
        dns_name, dns_domain = self._get_request_dns_name_and_domain_name(
            dns_data_db)
        for ip in ips:
            if dns_name:
                hostname = dns_name
                fqdn = dns_name
                if not dns_name.endswith('.'):
                    fqdn = '%s.%s' % (dns_name, dns_domain)
            else:
                hostname = 'host-%s' % ip['ip_address'].replace(
                    '.', '-').replace(':', '-')
                fqdn = hostname
                if dns_domain:
                    fqdn = '%s.%s' % (hostname, dns_domain)
            dns_assignment.append({'ip_address': ip['ip_address'],
                                   'hostname': hostname,
                                   'fqdn': fqdn})
        return dns_assignment

    def _get_dns_name_for_port_get(self, port, dns_data_db):
        if port['fixed_ips']:
            return self._get_dns_names_for_port(port['fixed_ips'], dns_data_db)
        return []

    def _extend_port_dict(self, session, db_data, response_data, dns_data_db):
        if not dns_data_db:
            response_data[dns_apidef.DNSNAME] = ''
        else:
            response_data[dns_apidef.DNSNAME] = dns_data_db[dns_apidef.DNSNAME]
        response_data['dns_assignment'] = self._get_dns_name_for_port_get(
            db_data, dns_data_db)
        return response_data

    def extend_port_dict(self, session, db_data, response_data):
        dns_data_db = db_data.dns
        return self._extend_port_dict(session, db_data, response_data,
                                      dns_data_db)

    def _get_network(self, context, network_id):
        plugin = directory.get_plugin()
        return plugin.get_network(context, network_id)


class DNSExtensionDriverML2(DNSExtensionDriver):

    def initialize(self):
        LOG.info("DNSExtensionDriverML2 initialization complete")

    def _is_tunnel_tenant_network(self, provider_net):
        if provider_net['network_type'] == 'geneve':
            tunnel_ranges = cfg.CONF.ml2_type_geneve.vni_ranges
        elif provider_net['network_type'] == 'vxlan':
            tunnel_ranges = cfg.CONF.ml2_type_vxlan.vni_ranges
        else:
            tunnel_ranges = cfg.CONF.ml2_type_gre.tunnel_id_ranges

        segmentation_id = int(provider_net['segmentation_id'])
        for entry in tunnel_ranges:
            entry = entry.strip()
            tun_min, tun_max = entry.split(':')
            tun_min = tun_min.strip()
            tun_max = tun_max.strip()
            return int(tun_min) <= segmentation_id <= int(tun_max)

    def _is_vlan_tenant_network(self, provider_net):
        network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
            cfg.CONF.ml2_type_vlan.network_vlan_ranges)
        vlan_ranges = network_vlan_ranges[provider_net['physical_network']]
        if not vlan_ranges:
            return False
        segmentation_id = int(provider_net['segmentation_id'])
        for vlan_range in vlan_ranges:
            if vlan_range[0] <= segmentation_id <= vlan_range[1]:
                return True

    def external_dns_not_needed(self, context, network):
        dns_driver = _get_dns_driver()
        if not dns_driver:
            return True
        if network['router:external']:
            return True
        segments = segments_db.get_network_segments(context, network['id'])
        if len(segments) > 1:
            return False
        provider_net = segments[0]
        if provider_net['network_type'] == 'local':
            return True
        if provider_net['network_type'] == 'flat':
            return False
        if provider_net['network_type'] == 'vlan':
            return self._is_vlan_tenant_network(provider_net)
        if provider_net['network_type'] in ['gre', 'vxlan', 'geneve']:
            return self._is_tunnel_tenant_network(provider_net)
        return True


class DNSDomainPortsExtensionDriver(DNSExtensionDriverML2):
    _supported_extension_aliases = [dns_apidef.ALIAS, dns_domain_ports.ALIAS]

    @property
    def extension_aliases(self):
        return self._supported_extension_aliases

    def initialize(self):
        LOG.info("DNSDomainPortsExtensionDriver initialization complete")

    def extend_port_dict(self, session, db_data, response_data):
        response_data = (
            super(DNSDomainPortsExtensionDriver, self).extend_port_dict(
                session, db_data, response_data))
        dns_data_db = db_data.dns
        response_data[dns_apidef.DNSDOMAIN] = ''
        if dns_data_db:
            response_data[dns_apidef.DNSDOMAIN] = dns_data_db[
                dns_apidef.DNSDOMAIN]


DNS_DRIVER = None


def _get_dns_driver():
    global DNS_DRIVER
    if DNS_DRIVER:
        return DNS_DRIVER
    if not cfg.CONF.external_dns_driver:
        return
    try:
        DNS_DRIVER = driver.ExternalDNSService.get_instance()
        LOG.debug("External DNS driver loaded: %s",
                  cfg.CONF.external_dns_driver)
        return DNS_DRIVER
    except ImportError:
        LOG.exception("ImportError exception occurred while loading "
                      "the external DNS service driver")
        raise dns_exc.ExternalDNSDriverNotFound(
            driver=cfg.CONF.external_dns_driver)


def _create_port_in_external_dns_service(resource, event, trigger, **kwargs):
    dns_driver = _get_dns_driver()
    if not dns_driver:
        return
    context = kwargs['context']
    port = kwargs['port']
    dns_data_db = port_obj.PortDNS.get_object(
        context, port_id=port['id'])
    if not (dns_data_db and dns_data_db['current_dns_name']):
        return
    records = [ip['ip_address'] for ip in port['fixed_ips']]
    _send_data_to_external_dns_service(context, dns_driver,
                                       dns_data_db['current_dns_domain'],
                                       dns_data_db['current_dns_name'],
                                       records)


def _send_data_to_external_dns_service(context, dns_driver, dns_domain,
                                       dns_name, records):
    try:
        dns_driver.create_record_set(context, dns_domain, dns_name, records)
    except (dns_exc.DNSDomainNotFound, dns_exc.DuplicateRecordSet) as e:
        LOG.exception("Error publishing port data in external DNS "
                      "service. Name: '%(name)s'. Domain: '%(domain)s'. "
                      "DNS service driver message '%(message)s'",
                      {"name": dns_name,
                       "domain": dns_domain,
                       "message": e.msg})


def _remove_data_from_external_dns_service(context, dns_driver, dns_domain,
                                           dns_name, records):
    try:
        dns_driver.delete_record_set(context, dns_domain, dns_name, records)
    except (dns_exc.DNSDomainNotFound, dns_exc.DuplicateRecordSet) as e:
        LOG.exception("Error deleting port data from external DNS "
                      "service. Name: '%(name)s'. Domain: '%(domain)s'. "
                      "IP addresses '%(ips)s'. DNS service driver message "
                      "'%(message)s'",
                      {"name": dns_name,
                       "domain": dns_domain,
                       "message": e.msg,
                       "ips": ', '.join(records)})


def _update_port_in_external_dns_service(resource, event, trigger, **kwargs):
    dns_driver = _get_dns_driver()
    if not dns_driver:
        return
    context = kwargs['context']
    updated_port = kwargs['port']
    original_port = kwargs.get('original_port')
    if not original_port:
        return
    original_ips = [ip['ip_address'] for ip in original_port['fixed_ips']]
    updated_ips = [ip['ip_address'] for ip in updated_port['fixed_ips']]
    is_dns_name_changed = (updated_port[dns_apidef.DNSNAME] !=
                           original_port[dns_apidef.DNSNAME])
    is_dns_domain_changed = (dns_apidef.DNSDOMAIN in updated_port and
                             updated_port[dns_apidef.DNSDOMAIN] !=
                             original_port[dns_apidef.DNSDOMAIN])
    ips_changed = set(original_ips) != set(updated_ips)
    if not any((is_dns_name_changed, is_dns_domain_changed, ips_changed)):
        return
    dns_data_db = port_obj.PortDNS.get_object(
        context, port_id=updated_port['id'])
    if not (dns_data_db and (dns_data_db['previous_dns_name'] or dns_data_db[
        'current_dns_name'])):
        return
    if dns_data_db['previous_dns_name']:
        _remove_data_from_external_dns_service(
            context, dns_driver, dns_data_db['previous_dns_domain'],
            dns_data_db['previous_dns_name'], original_ips)
    if dns_data_db['current_dns_name']:
        _send_data_to_external_dns_service(context, dns_driver,
                                           dns_data_db['current_dns_domain'],
                                           dns_data_db['current_dns_name'],
                                           updated_ips)


def _delete_port_in_external_dns_service(resource, event,
                                         trigger, payload=None):
    dns_driver = _get_dns_driver()
    if not dns_driver:
        return
    context = payload.context
    port_id = payload.resource_id
    dns_data_db = port_obj.PortDNS.get_object(
        context, port_id=port_id)
    if not dns_data_db:
        return
    if dns_data_db['current_dns_name']:
        ip_allocations = port_obj.IPAllocation.get_objects(context,
                                                           port_id=port_id)
        records = [str(alloc['ip_address']) for alloc in ip_allocations]
        _remove_data_from_external_dns_service(
            context, dns_driver, dns_data_db['current_dns_domain'],
            dns_data_db['current_dns_name'], records)


def subscribe():
    registry.subscribe(
        _create_port_in_external_dns_service, resources.PORT,
        events.AFTER_CREATE)
    registry.subscribe(
        _update_port_in_external_dns_service, resources.PORT,
        events.AFTER_UPDATE)
    registry.subscribe(
        _delete_port_in_external_dns_service, resources.PORT,
        events.BEFORE_DELETE)


subscribe()
