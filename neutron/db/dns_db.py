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
import sqlalchemy as sa
from sqlalchemy import orm

from neutron._i18n import _, _LE
from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc
from neutron.common import utils
from neutron.db import db_base_plugin_v2
from neutron.db import l3_db
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import dns
from neutron.extensions import l3
from neutron import manager
from neutron.plugins.common import constants as service_constants
from neutron.services.externaldns import driver

LOG = logging.getLogger(__name__)


class NetworkDNSDomain(model_base.BASEV2):
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True,
                           index=True)
    dns_domain = sa.Column(sa.String(255),
                           nullable=False)

    # Add a relationship to the Network model in order to instruct
    # SQLAlchemy to eagerly load this association
    network = orm.relationship(models_v2.Network,
                               backref=orm.backref("dns_domain",
                                                   lazy='joined',
                                                   uselist=False,
                                                   cascade='delete'))


class FloatingIPDNS(model_base.BASEV2):

    __tablename__ = 'floatingipdnses'

    floatingip_id = sa.Column(sa.String(36),
                              sa.ForeignKey('floatingips.id',
                                            ondelete="CASCADE"),
                              primary_key=True,
                              index=True)
    dns_name = sa.Column(sa.String(255),
                         nullable=False)
    dns_domain = sa.Column(sa.String(255),
                           nullable=False)
    published_dns_name = sa.Column(sa.String(255),
                                   nullable=False)
    published_dns_domain = sa.Column(sa.String(255),
                                     nullable=False)

    # Add a relationship to the FloatingIP model in order to instruct
    # SQLAlchemy to eagerly load this association
    floatingip = orm.relationship(l3_db.FloatingIP,
                                  backref=orm.backref("dns",
                                                      lazy='joined',
                                                      uselist=False,
                                                      cascade='delete'))


class PortDNS(model_base.BASEV2):

    __tablename__ = 'portdnses'

    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id',
                                      ondelete="CASCADE"),
                        primary_key=True,
                        index=True)
    current_dns_name = sa.Column(sa.String(255),
                                 nullable=False)
    current_dns_domain = sa.Column(sa.String(255),
                                   nullable=False)
    previous_dns_name = sa.Column(sa.String(255),
                                  nullable=False)
    previous_dns_domain = sa.Column(sa.String(255),
                                    nullable=False)

    # Add a relationship to the Port model in order to instruct
    # SQLAlchemy to eagerly load this association
    port = orm.relationship(models_v2.Port,
                            backref=orm.backref("dns",
                                                lazy='joined',
                                                uselist=False,
                                                cascade='delete'))


class DNSActionsData(object):

    def __init__(self, current_dns_name=None, current_dns_domain=None,
                 previous_dns_name=None, previous_dns_domain=None):
        self.current_dns_name = current_dns_name
        self.current_dns_domain = current_dns_domain
        self.previous_dns_name = previous_dns_name
        self.previous_dns_domain = previous_dns_domain


class DNSDbMixin(object):
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
            LOG.exception(_LE("ImportError exception occurred while loading "
                              "the external DNS service driver"))
            raise dns.ExternalDNSDriverNotFound(
                driver=cfg.CONF.external_dns_driver)

    def _extend_floatingip_dict_dns(self, floatingip_res, floatingip_db):
        floatingip_res['dns_domain'] = ''
        floatingip_res['dns_name'] = ''
        if floatingip_db.dns:
            floatingip_res['dns_domain'] = floatingip_db.dns['dns_domain']
            floatingip_res['dns_name'] = floatingip_db.dns['dns_name']
        return floatingip_res

    # Register dict extend functions for floating ips
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        l3.FLOATINGIPS, ['_extend_floatingip_dict_dns'])

    def _process_dns_floatingip_create_precommit(self, context,
                                                 floatingip_data, req_data):
        # expects to be called within a plugin's session
        dns_domain = req_data.get(dns.DNSDOMAIN)
        if not attributes.is_attr_set(dns_domain):
            return
        if not self.dns_driver:
            return

        dns_name = req_data[dns.DNSNAME]
        self._validate_floatingip_dns(dns_name, dns_domain)

        current_dns_name, current_dns_domain = (
            self._get_requested_state_for_external_dns_service_create(
                context, floatingip_data, req_data))
        dns_actions_data = None
        if current_dns_name and current_dns_domain:
            context.session.add(FloatingIPDNS(
                floatingip_id=floatingip_data['id'],
                dns_name=req_data[dns.DNSNAME],
                dns_domain=req_data[dns.DNSDOMAIN],
                published_dns_name=current_dns_name,
                published_dns_domain=current_dns_domain))
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
        plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if not utils.is_extension_supported(plugin, dns.Dns.get_alias()):
            return
        if not self.dns_driver:
            return
        dns_data_db = context.session.query(FloatingIPDNS).filter_by(
            floatingip_id=floatingip_data['id']).one_or_none()
        if dns_data_db and dns_data_db['dns_name']:
            # dns_name and dns_domain assigned for floating ip. It doesn't
            # matter whether they are defined for internal port
            return
        current_dns_name, current_dns_domain = (
            self._get_requested_state_for_external_dns_service_update(
                context, floatingip_data))
        if dns_data_db:
            if (dns_data_db['published_dns_name'] != current_dns_name or
                dns_data_db['published_dns_domain'] != current_dns_domain):
                dns_actions_data = DNSActionsData(
                    previous_dns_name=dns_data_db['published_dns_name'],
                    previous_dns_domain=dns_data_db['published_dns_domain'])
                if current_dns_name and current_dns_domain:
                    dns_data_db['published_dns_name'] = current_dns_name
                    dns_data_db['published_dns_domain'] = current_dns_domain
                    dns_actions_data.current_dns_name = current_dns_name
                    dns_actions_data.current_dns_domain = current_dns_domain
                else:
                    context.session.delete(dns_data_db)
                return dns_actions_data
            else:
                return
        if current_dns_name and current_dns_domain:
            context.session.add(FloatingIPDNS(
                floatingip_id=floatingip_data['id'],
                dns_name='',
                dns_domain='',
                published_dns_name=current_dns_name,
                published_dns_domain=current_dns_domain))
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
        plugin = manager.NeutronManager.get_service_plugins().get(
            service_constants.L3_ROUTER_NAT)
        if not utils.is_extension_supported(plugin, dns.Dns.get_alias()):
            return
        dns_data_db = context.session.query(FloatingIPDNS).filter_by(
            floatingip_id=floatingip_data['id']).one_or_none()
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
        internal_port = context.session.query(models_v2.Port).filter_by(
            id=floatingip_data['port_id']).one()
        dns_domain = None
        if internal_port['dns_name']:
            net_dns = context.session.query(NetworkDNSDomain).filter_by(
                network_id=internal_port['network_id']).one_or_none()
            if net_dns:
                dns_domain = net_dns['dns_domain']
        return internal_port['dns_name'], dns_domain

    def _delete_floatingip_from_external_dns_service(self, context, dns_domain,
                                                     dns_name, records):
        try:
            self.dns_driver.delete_record_set(context, dns_domain, dns_name,
                                              records)
        except (dns.DNSDomainNotFound, dns.DuplicateRecordSet) as e:
            LOG.exception(_LE("Error deleting Floating IP data from external "
                              "DNS service. Name: '%(name)s'. Domain: "
                              "'%(domain)s'. IP addresses '%(ips)s'. DNS "
                              "service driver message '%(message)s'")
                          % {"name": dns_name,
                             "domain": dns_domain,
                             "message": e.msg,
                             "ips": ', '.join(records)})

    def _get_requested_state_for_external_dns_service_create(self, context,
                                                             floatingip_data,
                                                             req_data):
        fip_dns_name = req_data[dns.DNSNAME]
        if fip_dns_name:
            return fip_dns_name, req_data[dns.DNSDOMAIN]
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
        try:
            self.dns_driver.create_record_set(context, dns_domain, dns_name,
                                              records)
        except (dns.DNSDomainNotFound, dns.DuplicateRecordSet) as e:
            LOG.exception(_LE("Error publishing floating IP data in external "
                              "DNS service. Name: '%(name)s'. Domain: "
                              "'%(domain)s'. DNS service driver message "
                              "'%(message)s'")
                          % {"name": dns_name,
                             "domain": dns_domain,
                             "message": e.msg})
