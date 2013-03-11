# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from quantum.common import constants as q_const
from quantum.common import rpc as q_rpc
from quantum.db import agents_db
from quantum.db import api as db_api
from quantum.db import dhcp_rpc_base
from quantum.db import l3_rpc_base
from quantum.db import securitygroups_rpc_base as sg_db_rpc
from quantum.openstack.common import log as logging
from quantum.plugins.mlnx.db import mlnx_db_v2 as db

LOG = logging.getLogger(__name__)


class MlnxRpcCallbacks(dhcp_rpc_base.DhcpRpcCallbackMixin,
                       l3_rpc_base.L3RpcCallbackMixin,
                       sg_db_rpc.SecurityGroupServerRpcCallbackMixin):
    # History
    #  1.1 Support Security Group RPC
    RPC_API_VERSION = '1.1'

    #to be compatible with Linux Bridge Agent on Network Node
    TAP_PREFIX_LEN = 3

    def __init__(self):
        pass

    def create_rpc_dispatcher(self):
        """Get the rpc dispatcher for this manager.

        If a manager would like to set an RPC API version,
        or support more than one class as the target of RPC messages,
        override this method.
        """
        return q_rpc.PluginRpcDispatcher([self,
                                          agents_db.AgentExtRpcCallback()])

    @classmethod
    def get_port_from_device(cls, device):
        """Get port according to device.

        To maintain compatibility with Linux Bridge L2 Agent for DHCP/L3
        services get device either by linux bridge plugin
        device name convention or by mac address
        """
        port = db.get_port_from_device(device[cls.TAP_PREFIX_LEN:])
        if port:
            port['device'] = device
        else:
            port = db.get_port_from_device_mac(device)
        return port

    def get_device_details(self, rpc_context, **kwargs):
        """Agent requests device details."""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug("Device %s details requested from %s", device, agent_id)
        port = self.get_port_from_device(device)
        if port:
            binding = db.get_network_binding(db_api.get_session(),
                                             port['network_id'])
            entry = {'device': device,
                     'physical_network': binding.physical_network,
                     'network_type': binding.network_type,
                     'vlan_id': binding.segmentation_id,
                     'network_id': port['network_id'],
                     'port_mac': port['mac_address'],
                     'port_id': port['id'],
                     'admin_state_up': port['admin_state_up']}
            # Set the port status to UP
            db.set_port_status(port['id'], q_const.PORT_STATUS_ACTIVE)
        else:
            entry = {'device': device}
            LOG.debug("%s can not be found in database", device)
        return entry

    def update_device_down(self, rpc_context, **kwargs):
        """Device no longer exists on agent."""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug(_("Device %(device)s no longer exists on %(agent_id)s"),
                  {'device': device, 'agent_id': agent_id})
        port = db.get_port_from_device(device)
        if port:
            entry = {'device': device,
                     'exists': True}
            # Set port status to DOWN
            db.set_port_status(port['id'], q_const.PORT_STATUS_DOWN)
        else:
            entry = {'device': device,
                     'exists': False}
            LOG.debug(_("%s can not be found in database"), device)
        return entry

    def update_device_up(self, rpc_context, **kwargs):
        """Device is up on agent."""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug(_("Device %(device)s up %(agent_id)s"),
                  {'device': device, 'agent_id': agent_id})
        port = self.get_port_from_device(device)
        if port:
            if port['status'] != q_const.PORT_STATUS_ACTIVE:
                # Set port status to ACTIVE
                db.set_port_status(port['id'], q_const.PORT_STATUS_ACTIVE)
        else:
            LOG.debug(_("%s can not be found in database"), device)
