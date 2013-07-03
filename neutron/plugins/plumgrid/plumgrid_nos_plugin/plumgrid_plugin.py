# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 PLUMgrid, Inc. All Rights Reserved.
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
#
# @author: Edgar Magana, emagana@plumgrid.com, PLUMgrid, Inc.

"""
Neutron PLUMgrid Plug-in for PLUMgrid Virtual Technology
This plugin will forward authenticated REST API calls
to the Network Operating System by PLUMgrid called NOS
"""

from oslo.config import cfg

from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.openstack.common import log as logging
from neutron.plugins.plumgrid.common import exceptions as plum_excep
from neutron.plugins.plumgrid.plumgrid_nos_plugin.plugin_ver import VERSION
from neutron.plugins.plumgrid.plumgrid_nos_plugin import plumgrid_nos_snippets
from neutron.plugins.plumgrid.plumgrid_nos_plugin import rest_connection


LOG = logging.getLogger(__name__)


nos_server_opts = [
    cfg.StrOpt('nos_server', default='localhost',
               help=_("PLUMgrid NOS server to connect to")),
    cfg.StrOpt('nos_server_port', default='8080',
               help=_("PLUMgrid NOS server port to connect to")),
    cfg.StrOpt('username', default='username',
               help=_("PLUMgrid NOS admin username")),
    cfg.StrOpt('password', default='password', secret=True,
               help=_("PLUMgrid NOS admin password")),
    cfg.IntOpt('servertimeout', default=5,
               help=_("PLUMgrid NOS server timeout")),
    cfg.IntOpt('topologyname', default='t1',
               help=_("PLUMgrid NOS topology name")), ]


cfg.CONF.register_opts(nos_server_opts, "PLUMgridNOS")


class NeutronPluginPLUMgridV2(db_base_plugin_v2.NeutronDbPluginV2):

    def __init__(self):
        LOG.info(_('NeutronPluginPLUMgrid Status: Starting Plugin'))

        # PLUMgrid NOS configuration
        nos_plumgrid = cfg.CONF.PLUMgridNOS.nos_server
        nos_port = cfg.CONF.PLUMgridNOS.nos_server_port
        timeout = cfg.CONF.PLUMgridNOS.servertimeout
        self.topology_name = cfg.CONF.PLUMgridNOS.topologyname
        self.snippets = plumgrid_nos_snippets.DataNOSPLUMgrid()

        # TODO(Edgar) These are placeholders for next PLUMgrid release
        cfg.CONF.PLUMgridNOS.username
        cfg.CONF.PLUMgridNOS.password
        self.rest_conn = rest_connection.RestConnection(nos_plumgrid,
                                                        nos_port, timeout)
        if self.rest_conn is None:
            raise SystemExit(_('NeutronPluginPLUMgrid Status: '
                               'Aborting Plugin'))

        else:
            # Plugin DB initialization
            db.configure_db()

            # PLUMgrid NOS info validation
            LOG.info(_('NeutronPluginPLUMgrid NOS: %s'), nos_plumgrid)
            if not nos_plumgrid:
                raise SystemExit(_('NeutronPluginPLUMgrid Status: '
                                   'NOS value is missing in config file'))

            LOG.debug(_('NeutronPluginPLUMgrid Status: Neutron server with '
                        'PLUMgrid Plugin has started'))

    def create_network(self, context, network):
        """Create network core Neutron API."""

        LOG.debug(_('NeutronPluginPLUMgrid Status: create_network() called'))

        # Plugin DB - Network Create and validation
        tenant_id = self._get_tenant_id_for_create(context,
                                                   network["network"])
        self._network_admin_state(network)

        with context.session.begin(subtransactions=True):
            net = super(NeutronPluginPLUMgridV2, self).create_network(context,
                                                                      network)

            try:
                LOG.debug(_('NeutronPluginPLUMgrid Status: %(tenant_id)s, '
                            '%(network)s, %(network_id)s'),
                          dict(
                              tenant_id=tenant_id,
                              network=network["network"],
                              network_id=net["id"],
                          ))
                nos_url = self.snippets.BASE_NOS_URL + net["id"]
                headers = {}
                body_data = self.snippets.create_domain_body_data(tenant_id)
                self.rest_conn.nos_rest_conn(nos_url,
                                             'PUT', body_data, headers)

            except Exception:
                err_message = _("PLUMgrid NOS communication failed")
                LOG.Exception(err_message)
                raise plum_excep.PLUMgridException(err_message)

        # return created network
        return net

    def update_network(self, context, net_id, network):
        """Update network core Neutron API."""

        LOG.debug(_("NeutronPluginPLUMgridV2.update_network() called"))
        self._network_admin_state(network)
        tenant_id = self._get_tenant_id_for_create(context, network["network"])

        with context.session.begin(subtransactions=True):
            # Plugin DB - Network Update
            new_network = super(
                NeutronPluginPLUMgridV2, self).update_network(context,
                                                              net_id, network)

            try:
                # PLUMgrid Server does not support updating resources yet
                nos_url = self.snippets.BASE_NOS_URL + net_id
                headers = {}
                body_data = {}
                self.rest_conn.nos_rest_conn(nos_url,
                                             'DELETE', body_data, headers)
                nos_url = self.snippets.BASE_NOS_URL + new_network["id"]
                body_data = self.snippets.create_domain_body_data(tenant_id)
                self.rest_conn.nos_rest_conn(nos_url,
                                             'PUT', body_data, headers)
            except Exception:
                err_message = _("PLUMgrid NOS communication failed")
                LOG.Exception(err_message)
                raise plum_excep.PLUMgridException(err_message)

        # return updated network
        return new_network

    def delete_network(self, context, net_id):
        """Delete network core Neutron API."""
        LOG.debug(_("NeutronPluginPLUMgrid Status: delete_network() called"))
        super(NeutronPluginPLUMgridV2, self).get_network(context, net_id)

        with context.session.begin(subtransactions=True):
            # Plugin DB - Network Delete
            super(NeutronPluginPLUMgridV2, self).delete_network(context,
                                                                net_id)

            try:
                nos_url = self.snippets.BASE_NOS_URL + net_id
                headers = {}
                body_data = {}
                self.rest_conn.nos_rest_conn(nos_url,
                                             'DELETE', body_data, headers)
            except Exception:
                err_message = _("PLUMgrid NOS communication failed")
                LOG.Exception(err_message)
                raise plum_excep.PLUMgridException(err_message)

    def create_port(self, context, port):
        """Create port core Neutron API."""
        LOG.debug(_("NeutronPluginPLUMgrid Status: create_port() called"))

        # Port operations on PLUMgrid NOS is an automatic operation from the
        # VIF driver operations in Nova. It requires admin_state_up to be True
        port["port"]["admin_state_up"] = True

        # Plugin DB - Port Create and Return port
        return super(NeutronPluginPLUMgridV2, self).create_port(context,
                                                                port)

    def update_port(self, context, port_id, port):
        """Update port core Neutron API."""
        LOG.debug(_("NeutronPluginPLUMgrid Status: update_port() called"))

        # Port operations on PLUMgrid NOS is an automatic operation from the
        # VIF driver operations in Nova.

        # Plugin DB - Port Update
        return super(NeutronPluginPLUMgridV2, self).update_port(
            context, port_id, port)

    def delete_port(self, context, port_id):
        """Delete port core Neutron API."""

        LOG.debug(_("NeutronPluginPLUMgrid Status: delete_port() called"))

        # Port operations on PLUMgrid NOS is an automatic operation from the
        # VIF driver operations in Nova.

        # Plugin DB - Port Delete
        super(NeutronPluginPLUMgridV2, self).delete_port(context, port_id)

    def create_subnet(self, context, subnet):
        """Create subnet core Neutron API."""

        LOG.debug(_("NeutronPluginPLUMgrid Status: create_subnet() called"))

        with context.session.begin(subtransactions=True):
            # Plugin DB - Subnet Create
            subnet = super(NeutronPluginPLUMgridV2, self).create_subnet(
                context, subnet)
            subnet_details = self._get_subnet(context, subnet["id"])
            net_id = subnet_details["network_id"]
            tenant_id = subnet_details["tenant_id"]

            try:
                nos_url = self.snippets.BASE_NOS_URL + net_id
                headers = {}
                body_data = self.snippets.create_network_body_data(
                    tenant_id, self.topology_name)
                self.rest_conn.nos_rest_conn(nos_url,
                                             'PUT', body_data, headers)
            except Exception:
                err_message = _("PLUMgrid NOS communication failed: ")
                LOG.Exception(err_message)
                raise plum_excep.PLUMgridException(err_message)

        return subnet

    def delete_subnet(self, context, subnet_id):
        """Delete subnet core Neutron API."""

        LOG.debug(_("NeutronPluginPLUMgrid Status: delete_subnet() called"))
        #Collecting subnet info
        subnet_details = self._get_subnet(context, subnet_id)

        with context.session.begin(subtransactions=True):
            # Plugin DB - Subnet Delete
            del_subnet = super(NeutronPluginPLUMgridV2, self).delete_subnet(
                context, subnet_id)
            try:
                headers = {}
                body_data = {}
                net_id = subnet_details["network_id"]
                self._cleaning_nos_subnet_structure(body_data, headers, net_id)
            except Exception:
                err_message = _("PLUMgrid NOS communication failed: ")
                LOG.Exception(err_message)
                raise plum_excep.PLUMgridException(err_message)

        return del_subnet

    def update_subnet(self, context, subnet_id, subnet):
        """Update subnet core Neutron API."""

        LOG.debug(_("update_subnet() called"))
        #Collecting subnet info
        initial_subnet = self._get_subnet(context, subnet_id)
        net_id = initial_subnet["network_id"]
        tenant_id = initial_subnet["tenant_id"]

        with context.session.begin(subtransactions=True):
            # Plugin DB - Subnet Update
            new_subnet = super(NeutronPluginPLUMgridV2, self).update_subnet(
                context, subnet_id, subnet)

            try:
                # PLUMgrid Server does not support updating resources yet
                headers = {}
                body_data = {}
                self._cleaning_nos_subnet_structure(body_data, headers, net_id)
                nos_url = self.snippets.BASE_NOS_URL + net_id
                body_data = self.snippets.create_network_body_data(
                    tenant_id, self.topology_name)
                self.rest_conn.nos_rest_conn(nos_url,
                                             'PUT', body_data, headers)

            except Exception:
                err_message = _("PLUMgrid NOS communication failed: ")
                LOG.Exception(err_message)
                raise plum_excep.PLUMgridException(err_message)

        return new_subnet

    """
    Extension API implementation
    """
    # TODO(Edgar) Complete extensions for PLUMgrid

    """
    Internal PLUMgrid fuctions
    """

    def _get_plugin_version(self):
        return VERSION

    def _cleaning_nos_subnet_structure(self, body_data, headers, net_id):
        domain_structure = ['/properties', '/link', '/ne']
        for structure in domain_structure:
            nos_url = self.snippets.BASE_NOS_URL + net_id + structure
            self.rest_conn.nos_rest_conn(nos_url, 'DELETE', body_data, headers)

    def _network_admin_state(self, network):
        try:
            if network["network"].get("admin_state_up"):
                network_name = network["network"]["name"]
                if network["network"]["admin_state_up"] is False:
                    LOG.warning(_("Network with admin_state_up=False are not "
                                  "supported yet by this plugin. Ignoring "
                                  "setting for network %s"), network_name)
        except Exception:
            err_message = _("Network Admin State Validation Falied: ")
            LOG.Exception(err_message)
            raise plum_excep.PLUMgridException(err_message)
        return network
