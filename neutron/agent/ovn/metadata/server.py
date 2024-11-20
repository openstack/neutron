# Copyright 2017 Red Hat, Inc.
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

import threading

from neutron.agent.linux import utils as agent_utils
from neutron.agent.metadata import proxy_base
from neutron.agent.ovn.metadata import ovsdb
from neutron.common.ovn import constants as ovn_const
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


class MetadataProxyHandler(proxy_base.MetadataProxyHandlerBase):
    NETWORK_ID_HEADER = 'X-OVN-Network-ID'
    ROUTER_ID_HEADER = ''

    def __init__(self, conf, chassis, sb_idl):
        super().__init__(conf)
        self.chassis = chassis
        self._sb_idl = sb_idl
        self._post_fork_event = threading.Event()
        self.subscribe()

    @property
    def sb_idl(self):
        if not self._sb_idl:
            self._post_fork_event.wait()

        return self._sb_idl

    @sb_idl.setter
    def sb_idl(self, val):
        self._sb_idl = val

    def subscribe(self):
        registry.subscribe(self.post_fork_initialize,
                           resources.PROCESS,
                           events.AFTER_INIT)

    def post_fork_initialize(self, resource, event, trigger, payload=None):
        # We need to open a connection to OVN SouthBound database for
        # each worker so that we can process the metadata requests.
        self._post_fork_event.clear()
        self.sb_idl = ovsdb.MetadataAgentOvnSbIdl(
            tables=('Port_Binding', 'Datapath_Binding', 'Chassis'),
            chassis=self.chassis).start()

        # Now IDL connections can be safely used.
        self._post_fork_event.set()

    def get_port(self, remote_address, network_id=None, remote_mac=None,
                 router_id=None, skip_cache=False):
        ports = self.sb_idl.get_network_port_bindings_by_ip(network_id,
                                                            remote_address,
                                                            mac=remote_mac)
        num_ports = len(ports)
        if num_ports == 1:
            external_ids = ports[0].external_ids
            return (external_ids[ovn_const.OVN_DEVID_EXT_ID_KEY],
                    external_ids[ovn_const.OVN_PROJID_EXT_ID_KEY])
        if num_ports == 0:
            LOG.error("No port found in network %s with IP address %s",
                      network_id, remote_address)
        elif num_ports > 1:
            port_uuids = ', '.join([str(port.uuid) for port in ports])
            LOG.error("More than one port found in network %s with IP address "
                      "%s. Please run the neutron-ovn-db-sync-util script as "
                      "there seems to be inconsistent data between Neutron "
                      "and OVN databases. OVN Port uuids: %s", network_id,
                      remote_address, port_uuids)
        return None, None


class UnixDomainMetadataProxy(proxy_base.UnixDomainMetadataProxyBase):

    def __init__(self, conf, chassis, sb_idl=None):
        super().__init__(conf)
        self.chassis = chassis
        self.sb_idl = sb_idl
        agent_utils.ensure_directory_exists_without_file(
            cfg.CONF.metadata_proxy_socket)

    def run(self):
        self.server = agent_utils.UnixDomainWSGIServer(
            'neutron-ovn-metadata-agent')
        # Set the default metadata_workers if not yet set in the config file
        md_workers = self.conf.metadata_workers
        md_workers = 0 if md_workers is None else md_workers
        sb_idl = self.sb_idl if md_workers == 0 else None
        self.server.start(MetadataProxyHandler(self.conf, self.chassis,
                                               sb_idl),
                          self.conf.metadata_proxy_socket,
                          workers=md_workers,
                          backlog=self.conf.metadata_backlog,
                          mode=self._get_socket_mode())

    def wait(self):
        self.server.wait()
