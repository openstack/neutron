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

from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _LE, _LI
from neutron.api.v2 import attributes
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.db import dns_db
from neutron.db import models_v2
from neutron.extensions import dns
from neutron import manager
from neutron.plugins.common import utils as plugin_utils
from neutron.plugins.ml2 import db
from neutron.plugins.ml2 import driver_api as api
from neutron.services.externaldns import driver

LOG = logging.getLogger(__name__)


class DNSExtensionDriver(api.ExtensionDriver):
    _supported_extension_alias = 'dns-integration'

    @property
    def extension_alias(self):
        return self._supported_extension_alias

    def process_create_network(self, plugin_context, request_data, db_data):
        dns_domain = request_data.get(dns.DNSDOMAIN)
        if not attributes.is_attr_set(dns_domain):
            return

        if dns_domain:
            plugin_context.session.add(dns_db.NetworkDNSDomain(
                network_id=db_data['id'], dns_domain=dns_domain))
        db_data[dns.DNSDOMAIN] = dns_domain

    def process_update_network(self, plugin_context, request_data, db_data):
        new_value = request_data.get(dns.DNSDOMAIN)
        if not attributes.is_attr_set(new_value):
            return

        current_dns_domain = db_data.get(dns.DNSDOMAIN)
        if current_dns_domain == new_value:
            return

        net_id = db_data['id']
        if current_dns_domain:
            net_dns_domain = plugin_context.session.query(
                dns_db.NetworkDNSDomain).filter_by(network_id=net_id).one()
            if new_value:
                net_dns_domain['dns_domain'] = new_value
                db_data[dns.DNSDOMAIN] = new_value
            else:
                plugin_context.session.delete(net_dns_domain)
                db_data[dns.DNSDOMAIN] = ''
        elif new_value:
            plugin_context.session.add(dns_db.NetworkDNSDomain(
                network_id=net_id, dns_domain=new_value))
            db_data[dns.DNSDOMAIN] = new_value

    def process_create_port(self, plugin_context, request_data, db_data):
        if not request_data[dns.DNSNAME]:
            return
        network = self._get_network(plugin_context, db_data['network_id'])
        if not network[dns.DNSDOMAIN]:
            return
        if self.external_dns_not_needed(plugin_context, network):
            return
        plugin_context.session.add(dns_db.PortDNS(
            port_id=db_data['id'],
            current_dns_name=request_data[dns.DNSNAME],
            current_dns_domain=network[dns.DNSDOMAIN],
            previous_dns_name='', previous_dns_domain=''))

    def process_update_port(self, plugin_context, request_data, db_data):
        dns_name = request_data.get(dns.DNSNAME)
        has_fixed_ips = 'fixed_ips' in request_data
        if dns_name is None and not has_fixed_ips:
            return
        network = self._get_network(plugin_context, db_data['network_id'])
        if not network[dns.DNSDOMAIN]:
            return
        if self.external_dns_not_needed(plugin_context, network):
            return
        dns_domain = network[dns.DNSDOMAIN]
        dns_data_db = plugin_context.session.query(dns_db.PortDNS).filter_by(
            port_id=db_data['id']).one_or_none()
        if dns_data_db:
            is_dns_name_changed = (dns_name is not None and
                    dns_data_db['current_dns_name'] != dns_name)

            if is_dns_name_changed or (has_fixed_ips and
                                       dns_data_db['current_dns_name']):
                dns_data_db['previous_dns_name'] = (
                    dns_data_db['current_dns_name'])
                dns_data_db['previous_dns_domain'] = (
                    dns_data_db['current_dns_domain'])
                if is_dns_name_changed:
                    dns_data_db['current_dns_name'] = dns_name
                    if dns_name:
                        dns_data_db['current_dns_domain'] = dns_domain
                    else:
                        dns_data_db['current_dns_domain'] = ''
            return
        if dns_name:
            plugin_context.session.add(dns_db.PortDNS(
                port_id=db_data['id'],
                current_dns_name=dns_name,
                current_dns_domain=dns_domain,
                previous_dns_name='', previous_dns_domain=''))

    def external_dns_not_needed(self, context, network):
        """Decide if ports in network need to be sent to the DNS service.

        :param context: plugin request context
        :param network: network dictionary
        :return True or False
        """
        pass

    def extend_network_dict(self, session, db_data, response_data):
        response_data[dns.DNSDOMAIN] = ''
        if db_data.dns_domain:
            response_data[dns.DNSDOMAIN] = db_data.dns_domain[dns.DNSDOMAIN]
        return response_data

    def extend_port_dict(self, session, db_data, response_data):
        response_data[dns.DNSNAME] = db_data[dns.DNSNAME]
        return response_data

    def _get_network(self, context, network_id):
        plugin = manager.NeutronManager.get_plugin()
        return plugin.get_network(context, network_id)


class DNSExtensionDriverML2(DNSExtensionDriver):

    def initialize(self):
        LOG.info(_LI("DNSExtensionDriverML2 initialization complete"))

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
        segments = db.get_network_segments(context.session, network['id'])
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
        LOG.exception(_LE("ImportError exception occurred while loading "
                          "the external DNS service driver"))
        raise dns.ExternalDNSDriverNotFound(
            driver=cfg.CONF.external_dns_driver)


def _create_port_in_external_dns_service(resource, event, trigger, **kwargs):
    dns_driver = _get_dns_driver()
    if not dns_driver:
        return
    context = kwargs['context']
    port = kwargs['port']
    dns_data_db = context.session.query(dns_db.PortDNS).filter_by(
        port_id=port['id']).one_or_none()
    if not dns_data_db:
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
    except (dns.DNSDomainNotFound, dns.DuplicateRecordSet) as e:
        LOG.exception(_LE("Error publishing port data in external DNS "
                          "service. Name: '%(name)s'. Domain: '%(domain)s'. "
                          "DNS service driver message '%(message)s'")
                      % {"name": dns_name,
                         "domain": dns_domain,
                         "message": e.msg})


def _remove_data_from_external_dns_service(context, dns_driver, dns_domain,
                                           dns_name, records):
    try:
        dns_driver.delete_record_set(context, dns_domain, dns_name, records)
    except (dns.DNSDomainNotFound, dns.DuplicateRecordSet) as e:
        LOG.exception(_LE("Error deleting port data from external DNS "
                          "service. Name: '%(name)s'. Domain: '%(domain)s'. "
                          "IP addresses '%(ips)s'. DNS service driver message "
                          "'%(message)s'")
                      % {"name": dns_name,
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
    if (updated_port[dns.DNSNAME] == original_port[dns.DNSNAME] and
            set(original_ips) == set(updated_ips)):
        return
    if (updated_port[dns.DNSNAME] == original_port[dns.DNSNAME] and
            not original_port[dns.DNSNAME]):
        return
    dns_data_db = context.session.query(dns_db.PortDNS).filter_by(
        port_id=updated_port['id']).one_or_none()
    if not dns_data_db:
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


def _delete_port_in_external_dns_service(resource, event, trigger, **kwargs):
    dns_driver = _get_dns_driver()
    if not dns_driver:
        return
    context = kwargs['context']
    port_id = kwargs['port_id']
    dns_data_db = context.session.query(dns_db.PortDNS).filter_by(
        port_id=port_id).one_or_none()
    if not dns_data_db:
        return
    if dns_data_db['current_dns_name']:
        ip_allocations = context.session.query(
            models_v2.IPAllocation).filter_by(port_id=port_id).all()
        records = [alloc['ip_address'] for alloc in ip_allocations]
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
