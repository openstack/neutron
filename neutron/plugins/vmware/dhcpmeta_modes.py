# Copyright 2013 VMware, Inc.
#
# All Rights Reserved
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

from oslo.config import cfg

from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api
from neutron.common import constants as const
from neutron.common import topics
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import rpc
from neutron.plugins.vmware.common import config
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron.plugins.vmware.dhcp_meta import combined
from neutron.plugins.vmware.dhcp_meta import lsnmanager
from neutron.plugins.vmware.dhcp_meta import migration
from neutron.plugins.vmware.dhcp_meta import nsx as nsx_svc
from neutron.plugins.vmware.dhcp_meta import rpc as nsx_rpc
from neutron.plugins.vmware.extensions import lsn

LOG = logging.getLogger(__name__)


class DhcpMetadataAccess(object):

    def setup_dhcpmeta_access(self):
        """Initialize support for DHCP and Metadata services."""
        self._init_extensions()
        if cfg.CONF.NSX.agent_mode == config.AgentModes.AGENT:
            self._setup_rpc_dhcp_metadata()
            mod = nsx_rpc
        elif cfg.CONF.NSX.agent_mode == config.AgentModes.AGENTLESS:
            self._setup_nsx_dhcp_metadata()
            mod = nsx_svc
        elif cfg.CONF.NSX.agent_mode == config.AgentModes.COMBINED:
            notifier = self._setup_nsx_dhcp_metadata()
            self._setup_rpc_dhcp_metadata(notifier=notifier)
            mod = combined
        else:
            error = _("Invalid agent_mode: %s") % cfg.CONF.NSX.agent_mode
            LOG.error(error)
            raise nsx_exc.NsxPluginException(err_msg=error)
        self.handle_network_dhcp_access_delegate = (
            mod.handle_network_dhcp_access
        )
        self.handle_port_dhcp_access_delegate = (
            mod.handle_port_dhcp_access
        )
        self.handle_port_metadata_access_delegate = (
            mod.handle_port_metadata_access
        )
        self.handle_metadata_access_delegate = (
            mod.handle_router_metadata_access
        )

    def _setup_rpc_dhcp_metadata(self, notifier=None):
        self.topic = topics.PLUGIN
        self.conn = rpc.create_connection(new=True)
        self.dispatcher = nsx_rpc.NSXRpcCallbacks().create_rpc_dispatcher()
        self.conn.create_consumer(self.topic, self.dispatcher, fanout=False)
        self.agent_notifiers[const.AGENT_TYPE_DHCP] = (
            notifier or dhcp_rpc_agent_api.DhcpAgentNotifyAPI())
        self.conn.consume_in_thread()
        self.network_scheduler = importutils.import_object(
            cfg.CONF.network_scheduler_driver
        )
        self.supported_extension_aliases.extend(
            ['agent', 'dhcp_agent_scheduler'])

    def _setup_nsx_dhcp_metadata(self):
        self._check_services_requirements()
        nsx_svc.register_dhcp_opts(cfg)
        nsx_svc.register_metadata_opts(cfg)
        lsnmanager.register_lsn_opts(cfg)
        lsn_manager = lsnmanager.PersistentLsnManager(self)
        self.lsn_manager = lsn_manager
        if cfg.CONF.NSX.agent_mode == config.AgentModes.AGENTLESS:
            notifier = nsx_svc.DhcpAgentNotifyAPI(self, lsn_manager)
            self.agent_notifiers[const.AGENT_TYPE_DHCP] = notifier
            # In agentless mode, ports whose owner is DHCP need to
            # be special cased; so add it to the list of special
            # owners list
            if const.DEVICE_OWNER_DHCP not in self.port_special_owners:
                self.port_special_owners.append(const.DEVICE_OWNER_DHCP)
        elif cfg.CONF.NSX.agent_mode == config.AgentModes.COMBINED:
            # This becomes ineffective, as all new networks creations
            # are handled by Logical Services Nodes in NSX
            cfg.CONF.set_override('network_auto_schedule', False)
            LOG.warn(_('network_auto_schedule has been disabled'))
            notifier = combined.DhcpAgentNotifyAPI(self, lsn_manager)
            self.supported_extension_aliases.append(lsn.EXT_ALIAS)
            # Add the capability to migrate dhcp and metadata services over
            self.migration_manager = (
                migration.MigrationManager(self, lsn_manager, notifier))
        return notifier

    def _init_extensions(self):
        extensions = (lsn.EXT_ALIAS, 'agent', 'dhcp_agent_scheduler')
        for ext in extensions:
            if ext in self.supported_extension_aliases:
                self.supported_extension_aliases.remove(ext)

    def _check_services_requirements(self):
        try:
            error = None
            nsx_svc.check_services_requirements(self.cluster)
        except nsx_exc.InvalidVersion:
            error = _("Unable to run Neutron with config option '%s', as NSX "
                      "does not support it") % cfg.CONF.NSX.agent_mode
        except nsx_exc.ServiceClusterUnavailable:
            error = _("Unmet dependency for config option "
                      "'%s'") % cfg.CONF.NSX.agent_mode
        if error:
            LOG.exception(error)
            raise nsx_exc.NsxPluginException(err_msg=error)

    def get_lsn(self, context, network_id, fields=None):
        report = self.migration_manager.report(context, network_id)
        return {'network': network_id, 'report': report}

    def create_lsn(self, context, lsn):
        network_id = lsn['lsn']['network']
        subnet = self.migration_manager.validate(context, network_id)
        subnet_id = None if not subnet else subnet['id']
        self.migration_manager.migrate(context, network_id, subnet)
        r = self.migration_manager.report(context, network_id, subnet_id)
        return {'network': network_id, 'report': r}

    def handle_network_dhcp_access(self, context, network, action):
        self.handle_network_dhcp_access_delegate(self, context,
                                                 network, action)

    def handle_port_dhcp_access(self, context, port_data, action):
        self.handle_port_dhcp_access_delegate(self, context, port_data, action)

    def handle_port_metadata_access(self, context, port, is_delete=False):
        self.handle_port_metadata_access_delegate(self, context,
                                                  port, is_delete)

    def handle_router_metadata_access(self, context,
                                      router_id, interface=None):
        self.handle_metadata_access_delegate(self, context,
                                             router_id, interface)
