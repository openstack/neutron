# Copyright 2025 Red Hat, Inc.
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

import socketserver

from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.linux import utils as agent_utils
from neutron.agent.metadata import proxy_base
from neutron.common import metadata as common_metadata
from neutron.common.ovn import constants as ovn_const


LOG = logging.getLogger(__name__)


class MetadataProxyHandler(
        common_metadata.MetadataProxyHandlerBaseSocketServer):
    NETWORK_ID_HEADER = 'X-OVN-Network-ID'
    ROUTER_ID_HEADER = ''
    _conf = None
    _chassis = None
    _sb_idl = None

    def __init__(self, request, client_address, server):
        super().__init__(self._conf, has_cache=False, request=request,
                         client_address=client_address, server=server)

    @property
    def sb_idl(self):
        return self._sb_idl

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
            LOG.warning("No port found in network %s with IP address %s",
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
        self._server = None

    def run(self):
        file_socket = cfg.CONF.metadata_proxy_socket
        self._server = socketserver.ThreadingUnixStreamServer(
            file_socket, MetadataProxyHandler)
        MetadataProxyHandler._conf = self.conf
        MetadataProxyHandler._chassis = self.chassis
        MetadataProxyHandler._sb_idl = self.sb_idl

    def wait(self):
        self._server.serve_forever()
