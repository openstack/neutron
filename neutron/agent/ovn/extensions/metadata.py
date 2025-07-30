# Copyright 2024 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import functools
import re
import threading

from oslo_config import cfg
from oslo_log import log
from ovsdbapp.backend.ovs_idl import event as row_event
from ovsdbapp.backend.ovs_idl import vlog

from neutron.agent.linux import external_process
from neutron.agent.ovn.extensions import extension_manager
from neutron.agent.ovn.metadata import agent as metadata_agent
from neutron.agent.ovn.metadata import server_socket as metadata_server
from neutron.common.ovn import constants as ovn_const
from neutron.conf.agent.database import agents_db
from neutron.conf.agent.metadata import config as meta_conf
from neutron.conf.agent.ovn.metadata import config as ovn_meta
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf as config


LOG = log.getLogger(__name__)
EXT_NAME = 'metadata'
agents_db.register_db_agents_opts()
_SYNC_STATE_LOCK = threading.RLock()
CHASSIS_METADATA_LOCK = 'chassis_metadata_lock'

SB_IDL_TABLES = ['Encap',
                 'Port_Binding',
                 'Datapath_Binding',
                 'SB_Global',
                 'Chassis',
                 'Chassis_Private',
                 ]

NS_PREFIX = ovn_const.OVN_METADATA_PREFIX
MAC_PATTERN = re.compile(r'([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', re.I)
OVN_VIF_PORT_TYPES = (
    "", ovn_const.LSP_TYPE_EXTERNAL, ovn_const.LSP_TYPE_LOCALPORT)

MetadataPortInfo = collections.namedtuple('MetadataPortInfo', ['mac',
                                                               'ip_addresses',
                                                               'logical_port'])


def _sync_lock(f):
    """Decorator to block all operations for a global sync call."""
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        with _SYNC_STATE_LOCK:
            return f(*args, **kwargs)
    return wrapped


class ChassisPrivateCreateEvent(extension_manager.OVNExtensionEvent,
                                row_event.RowEvent):
    """Row create event - Chassis name == our_chassis."""
    def __init__(self, ovn_agent):
        self._first_time = True
        events = (self.ROW_CREATE,)
        super().__init__(events, 'Chassis_Private', None,
                         extension_name='metadata')
        self._agent = ovn_agent
        self.conditions = (('name', '=', self._agent.chassis),)
        self.event_name = self.__class__.__name__

    def run(self, event, row, old):
        if self._first_time:
            self._first_time = False
            return

        # Re-register the OVN agent with the local chassis in case its
        # entry was re-created (happens when restarting the ovn-controller)
        self.agent._update_chassis_private_config()
        self.agent.sync()


class MetadataExtension(extension_manager.OVNAgentExtension,
                        metadata_agent.MetadataAgent):

    def __init__(self):
        super().__init__(conf=cfg.CONF)
        vlog.use_python_logger(max_level=config.get_ovn_ovsdb_log_level())
        self._process_monitor = None
        self._proxy = None
        # We'll restart all haproxy instances upon start so that they honor
        # any potential changes in their configuration.
        self.restarted_metadata_proxy_set = set()

    @staticmethod
    def _register_config_options():
        ovn_meta.register_meta_conf_opts(meta_conf.SHARED_OPTS)
        ovn_meta.register_meta_conf_opts(
            meta_conf.UNIX_DOMAIN_METADATA_PROXY_OPTS)
        ovn_meta.register_meta_conf_opts(meta_conf.METADATA_PROXY_HANDLER_OPTS)
        ovn_meta.register_meta_conf_opts(meta_conf.METADATA_RATE_LIMITING_OPTS,
                                         group=meta_conf.RATE_LIMITING_GROUP)

    def initialize(self, *args):
        self._register_config_options()
        self._process_monitor = external_process.ProcessMonitor(
            config=self.agent_api.conf, resource_type='metadata')

    @property
    def name(self):
        return 'Metadata OVN agent extension'

    @property
    def ovs_idl_events(self):
        return []

    @property
    def nb_idl_tables(self):
        return []

    @property
    def nb_idl_events(self):
        return []

    @property
    def sb_idl_tables(self):
        return SB_IDL_TABLES

    @property
    def sb_idl_events(self):
        return [metadata_agent.PortBindingUpdatedEvent,
                metadata_agent.PortBindingDeletedEvent,
                metadata_agent.PortBindingCreateWithChassis,
                ChassisPrivateCreateEvent,
                ]

    # NOTE(ralonsoh): the following properties are needed during the migration
    # to the Metadata agent to the OVN agent, while sharing the code with
    # ``metadata_agent.MetadataAgent``
    @property
    def nb_idl(self):
        return self.agent_api.nb_idl

    @nb_idl.setter
    def nb_idl(self, val):
        self.agent_api.nb_idl = val

    @property
    def sb_idl(self):
        return self.agent_api.sb_idl

    @sb_idl.setter
    def sb_idl(self, val):
        self.agent_api.sb_idl = val

    @property
    def ovs_idl(self):
        return self.agent_api.ovs_idl

    @property
    def conf(self):
        return self.agent_api.conf

    @property
    def chassis(self):
        return self.agent_api.chassis

    @property
    def ovn_bridge(self):
        return self.agent_api.ovn_bridge

    @_sync_lock
    def resync(self):
        """Resync the Metadata OVN agent extension.

        Reload the configuration and sync the agent again.
        """
        self.agent_api.load_config()
        self._update_chassis_private_config()
        self.sync()

    def start(self):
        self._load_config()

        # Launch the server that will act as a proxy between the VM's and Nova.
        self._proxy = metadata_server.UnixDomainMetadataProxy(
            self.agent_api.conf, self.agent_api.chassis,
            sb_idl=self.agent_api.sb_idl)
        self._proxy.run()

        # Do the initial sync.
        self.sync(provision=False)

        # Register the agent with its corresponding Chassis
        self._update_chassis_private_config()

        # Start the metadata server.
        proxy_thread = threading.Thread(target=self._proxy.wait)
        proxy_thread.start()

        # Raise the "is_started" flag.
        self._is_started = True
