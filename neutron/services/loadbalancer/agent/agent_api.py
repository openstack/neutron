# Copyright 2013 New Dream Network, LLC (DreamHost)
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

from oslo import messaging

from neutron.common import rpc as n_rpc


class LbaasAgentApi(object):
    """Agent side of the Agent to Plugin RPC API."""

    # history
    #   1.0 Initial version
    #   2.0 Generic API for agent based drivers
    #       - get_logical_device() handling changed on plugin side;
    #       - pool_deployed() and update_status() methods added;

    def __init__(self, topic, context, host):
        self.context = context
        self.host = host
        target = messaging.Target(topic=topic, version='2.0')
        self.client = n_rpc.get_client(target)

    def get_ready_devices(self):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_ready_devices', host=self.host)

    def pool_destroyed(self, pool_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'pool_destroyed', pool_id=pool_id)

    def pool_deployed(self, pool_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'pool_deployed', pool_id=pool_id)

    def get_logical_device(self, pool_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_logical_device', pool_id=pool_id)

    def update_status(self, obj_type, obj_id, status):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'update_status', obj_type=obj_type,
                          obj_id=obj_id, status=status)

    def plug_vip_port(self, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'plug_vip_port', port_id=port_id,
                          host=self.host)

    def unplug_vip_port(self, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'unplug_vip_port', port_id=port_id,
                          host=self.host)

    def update_pool_stats(self, pool_id, stats):
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'update_pool_stats', pool_id=pool_id,
                          stats=stats, host=self.host)
