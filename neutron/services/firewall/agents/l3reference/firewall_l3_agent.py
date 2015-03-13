# Copyright (c) 2013 OpenStack Foundation.
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
from oslo_utils import importutils

from neutron.agent.linux import ip_lib
from neutron.common import exceptions as nexception
from neutron.common import topics
from neutron import context
from neutron.i18n import _LE
from neutron.plugins.common import constants
from neutron.services.firewall.agents import firewall_agent_api as api
from neutron.services import provider_configuration as provconf

LOG = logging.getLogger(__name__)


class FWaaSL3PluginApi(api.FWaaSPluginApiMixin):
    """Agent side of the FWaaS agent to FWaaS Plugin RPC API."""

    def __init__(self, topic, host):
        super(FWaaSL3PluginApi, self).__init__(topic, host)

    def get_firewalls_for_tenant(self, context, **kwargs):
        """Get the Firewalls with rules from the Plugin to send to driver."""
        LOG.debug("Retrieve Firewall with rules from Plugin")
        cctxt = self.client.prepare()
        return cctxt.call(context, 'get_firewalls_for_tenant', host=self.host)

    def get_tenants_with_firewalls(self, context, **kwargs):
        """Get all Tenants that have Firewalls configured from plugin."""
        LOG.debug("Retrieve Tenants with Firewalls configured from Plugin")
        cctxt = self.client.prepare()
        return cctxt.call(context,
                          'get_tenants_with_firewalls', host=self.host)


class FWaaSL3AgentRpcCallback(api.FWaaSAgentRpcCallbackMixin):
    """FWaaS Agent support to be used by Neutron L3 agent."""

    def __init__(self, conf):
        LOG.debug("Initializing firewall agent")
        self.conf = conf
        fwaas_driver_class_path = provconf.get_provider_driver_class(
            cfg.CONF.fwaas.driver)
        self.fwaas_enabled = cfg.CONF.fwaas.enabled

        # None means l3-agent has no information on the server
        # configuration due to the lack of RPC support.
        if self.neutron_service_plugins is not None:
            fwaas_plugin_configured = (constants.FIREWALL
                                       in self.neutron_service_plugins)
            if fwaas_plugin_configured and not self.fwaas_enabled:
                msg = _("FWaaS plugin is configured in the server side, but "
                        "FWaaS is disabled in L3-agent.")
                LOG.error(msg)
                raise SystemExit(1)
            self.fwaas_enabled = self.fwaas_enabled and fwaas_plugin_configured

        if self.fwaas_enabled:
            try:
                self.fwaas_driver = importutils.import_object(
                    fwaas_driver_class_path)
                LOG.debug("FWaaS Driver Loaded: '%s'", fwaas_driver_class_path)
            except ImportError:
                msg = _('Error importing FWaaS device driver: %s')
                raise ImportError(msg % fwaas_driver_class_path)
        self.services_sync = False
        # setup RPC to msg fwaas plugin
        self.fwplugin_rpc = FWaaSL3PluginApi(topics.FIREWALL_PLUGIN,
                                             conf.host)
        super(FWaaSL3AgentRpcCallback, self).__init__(host=conf.host)

    def _get_router_info_list_for_tenant(self, routers, tenant_id):
        """Returns the list of router info objects on which to apply the fw."""
        root_ip = ip_lib.IPWrapper()
        # Get the routers for the tenant
        router_ids = [
            router['id']
            for router in routers
            if router['tenant_id'] == tenant_id]
        local_ns_list = (root_ip.get_namespaces()
                         if self.conf.use_namespaces else [])

        router_info_list = []
        # Pick up namespaces for Tenant Routers
        for rid in router_ids:
            # for routers without an interface - get_routers returns
            # the router - but this is not yet populated in router_info
            if rid not in self.router_info:
                continue
            if self.conf.use_namespaces:
                router_ns = self.router_info[rid].ns_name
                if router_ns in local_ns_list:
                    router_info_list.append(self.router_info[rid])
            else:
                router_info_list.append(self.router_info[rid])
        return router_info_list

    def _invoke_driver_for_plugin_api(self, context, fw, func_name):
        """Invoke driver method for plugin API and provide status back."""
        LOG.debug("%(func_name)s from agent for fw: %(fwid)s",
                  {'func_name': func_name, 'fwid': fw['id']})
        try:
            routers = self.plugin_rpc.get_routers(context)
            router_info_list = self._get_router_info_list_for_tenant(
                routers,
                fw['tenant_id'])
            if not router_info_list:
                LOG.debug('No Routers on tenant: %s', fw['tenant_id'])
                # fw was created before any routers were added, and if a
                # delete is sent then we need to ack so that plugin can
                # cleanup.
                if func_name == 'delete_firewall':
                    self.fwplugin_rpc.firewall_deleted(context, fw['id'])
                return
            LOG.debug("Apply fw on Router List: '%s'",
                      [ri.router['id'] for ri in router_info_list])
            # call into the driver
            try:
                self.fwaas_driver.__getattribute__(func_name)(
                    self.conf.agent_mode,
                    router_info_list,
                    fw)
                if fw['admin_state_up']:
                    status = constants.ACTIVE
                else:
                    status = constants.DOWN
            except nexception.FirewallInternalDriverError:
                LOG.error(_LE("Firewall Driver Error for %(func_name)s "
                              "for fw: %(fwid)s"),
                          {'func_name': func_name, 'fwid': fw['id']})
                status = constants.ERROR
            # delete needs different handling
            if func_name == 'delete_firewall':
                if status in [constants.ACTIVE, constants.DOWN]:
                    self.fwplugin_rpc.firewall_deleted(context, fw['id'])
            else:
                self.fwplugin_rpc.set_firewall_status(
                    context,
                    fw['id'],
                    status)
        except Exception:
            LOG.exception(
                _LE("FWaaS RPC failure in %(func_name)s for fw: %(fwid)s"),
                {'func_name': func_name, 'fwid': fw['id']})
            self.services_sync = True
        return

    def _invoke_driver_for_sync_from_plugin(self, ctx, router_info_list, fw):
        """Invoke the delete driver method for status of PENDING_DELETE and
        update method for all other status to (re)apply on driver which is
        Idempotent.
        """
        if fw['status'] == constants.PENDING_DELETE:
            try:
                self.fwaas_driver.delete_firewall(
                    self.conf.agent_mode,
                    router_info_list,
                    fw)
                self.fwplugin_rpc.firewall_deleted(
                    ctx,
                    fw['id'])
            except nexception.FirewallInternalDriverError:
                LOG.error(_LE("Firewall Driver Error on fw state %(fwmsg)s "
                              "for fw: %(fwid)s"),
                          {'fwmsg': fw['status'], 'fwid': fw['id']})
                self.fwplugin_rpc.set_firewall_status(
                    ctx,
                    fw['id'],
                    constants.ERROR)
        else:
            # PENDING_UPDATE, PENDING_CREATE, ...
            try:
                self.fwaas_driver.update_firewall(
                    self.conf.agent_mode,
                    router_info_list,
                    fw)
                if fw['admin_state_up']:
                    status = constants.ACTIVE
                else:
                    status = constants.DOWN
            except nexception.FirewallInternalDriverError:
                LOG.error(_LE("Firewall Driver Error on fw state %(fwmsg)s "
                              "for fw: %(fwid)s"),
                          {'fwmsg': fw['status'], 'fwid': fw['id']})
                status = constants.ERROR

            self.fwplugin_rpc.set_firewall_status(
                ctx,
                fw['id'],
                status)

    def _process_router_add(self, ri):
        """On router add, get fw with rules from plugin and update driver."""
        LOG.debug("Process router add, router_id: '%s'", ri.router['id'])
        routers = []
        routers.append(ri.router)
        router_info_list = self._get_router_info_list_for_tenant(
            routers,
            ri.router['tenant_id'])
        if router_info_list:
            # Get the firewall with rules
            # for the tenant the router is on.
            ctx = context.Context('', ri.router['tenant_id'])
            fw_list = self.fwplugin_rpc.get_firewalls_for_tenant(ctx)
            LOG.debug("Process router add, fw_list: '%s'",
                      [fw['id'] for fw in fw_list])
            for fw in fw_list:
                self._invoke_driver_for_sync_from_plugin(
                    ctx,
                    router_info_list,
                    fw)

    def process_router_add(self, ri):
        """On router add, get fw with rules from plugin and update driver."""
        # avoid msg to plugin when fwaas is not configured
        if not self.fwaas_enabled:
            return
        try:
            self._process_router_add(ri)
        except Exception:
            LOG.exception(
                _LE("FWaaS RPC info call failed for '%s'."),
                ri.router['id'])
            self.services_sync = True

    def process_services_sync(self, ctx):
        """On RPC issues sync with plugin and apply the sync data."""
        # avoid msg to plugin when fwaas is not configured
        if not self.fwaas_enabled:
            return
        try:
            # get all routers
            routers = self.plugin_rpc.get_routers(ctx)
            # get the list of tenants with firewalls configured
            # from the plugin
            tenant_ids = self.fwplugin_rpc.get_tenants_with_firewalls(ctx)
            LOG.debug("Tenants with Firewalls: '%s'", tenant_ids)
            for tenant_id in tenant_ids:
                ctx = context.Context('', tenant_id)
                fw_list = self.fwplugin_rpc.get_firewalls_for_tenant(ctx)
                if fw_list:
                    # if fw present on tenant
                    router_info_list = self._get_router_info_list_for_tenant(
                        routers,
                        tenant_id)
                    if router_info_list:
                        LOG.debug("Router List: '%s'",
                                  [ri.router['id'] for ri in router_info_list])
                        LOG.debug("fw_list: '%s'",
                                  [fw['id'] for fw in fw_list])
                        # apply sync data on fw for this tenant
                        for fw in fw_list:
                            # fw, routers present on this host for tenant
                            # install
                            LOG.debug("Apply fw on Router List: '%s'",
                                      [ri.router['id']
                                          for ri in router_info_list])
                            # no need to apply sync data for ACTIVE fw
                            if fw['status'] != constants.ACTIVE:
                                self._invoke_driver_for_sync_from_plugin(
                                    ctx,
                                    router_info_list,
                                    fw)
            self.services_sync = False
        except Exception:
            LOG.exception(_LE("Failed fwaas process services sync"))
            self.services_sync = True

    def create_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to create a firewall."""
        return self._invoke_driver_for_plugin_api(
            context,
            firewall,
            'create_firewall')

    def update_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to update a firewall."""
        return self._invoke_driver_for_plugin_api(
            context,
            firewall,
            'update_firewall')

    def delete_firewall(self, context, firewall, host):
        """Handle Rpc from plugin to delete a firewall."""
        return self._invoke_driver_for_plugin_api(
            context,
            firewall,
            'delete_firewall')
