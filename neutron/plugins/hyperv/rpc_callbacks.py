# Copyright 2013 Cloudbase Solutions SRL
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

import oslo_messaging

from neutron.common import constants as q_const
from neutron.openstack.common import log as logging
from neutron.plugins.hyperv import db as hyperv_db


LOG = logging.getLogger(__name__)


class HyperVRpcCallbacks(object):

    # history
    # 1.1 Support Security Group RPC
    # 1.2 Support get_devices_details_list
    target = oslo_messaging.Target(version='1.2')

    def __init__(self, notifier):
        super(HyperVRpcCallbacks, self).__init__()
        self.notifier = notifier
        self._db = hyperv_db.HyperVPluginDB()

    def get_device_details(self, rpc_context, **kwargs):
        """Agent requests device details."""
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug("Device %(device)s details requested from %(agent_id)s",
                  {'device': device, 'agent_id': agent_id})
        port = self._db.get_port(device)
        if port:
            binding = self._db.get_network_binding(None, port['network_id'])
            entry = {'device': device,
                     'network_id': port['network_id'],
                     'port_id': port['id'],
                     'admin_state_up': port['admin_state_up'],
                     'network_type': binding.network_type,
                     'segmentation_id': binding.segmentation_id,
                     'physical_network': binding.physical_network}
            # Set the port status to UP
            self._db.set_port_status(port['id'], q_const.PORT_STATUS_ACTIVE)
        else:
            entry = {'device': device}
            LOG.debug("%s can not be found in database", device)
        return entry

    def get_devices_details_list(self, rpc_context, **kwargs):
        return [
            self.get_device_details(
                rpc_context,
                device=device,
                **kwargs
            )
            for device in kwargs.pop('devices', [])
        ]

    def update_device_down(self, rpc_context, **kwargs):
        """Device no longer exists on agent."""
        # TODO(garyk) - live migration and port status
        agent_id = kwargs.get('agent_id')
        device = kwargs.get('device')
        LOG.debug("Device %(device)s no longer exists on %(agent_id)s",
                  {'device': device, 'agent_id': agent_id})
        port = self._db.get_port(device)
        if port:
            entry = {'device': device,
                     'exists': True}
            # Set port status to DOWN
            self._db.set_port_status(port['id'], q_const.PORT_STATUS_DOWN)
        else:
            entry = {'device': device,
                     'exists': False}
            LOG.debug("%s can not be found in database", device)
        return entry

    def tunnel_sync(self, rpc_context, **kwargs):
        """Tunnel sync.

        Dummy function for ovs agent running on Linux to
        work with Hyper-V plugin and agent.
        """
        entry = dict()
        entry['tunnels'] = {}
        # Return the list of tunnels IP's to the agent
        return entry
