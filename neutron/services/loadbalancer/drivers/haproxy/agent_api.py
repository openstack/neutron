# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
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
#
# @author: Mark McClain, DreamHost

from neutron.openstack.common.rpc import proxy


class LbaasAgentApi(proxy.RpcProxy):
    """Agent side of the Agent to Plugin RPC API."""

    API_VERSION = '1.0'

    def __init__(self, topic, context, host):
        super(LbaasAgentApi, self).__init__(topic, self.API_VERSION)
        self.context = context
        self.host = host

    def get_ready_devices(self):
        return self.call(
            self.context,
            self.make_msg('get_ready_devices', host=self.host),
            topic=self.topic
        )

    def get_logical_device(self, pool_id):
        return self.call(
            self.context,
            self.make_msg(
                'get_logical_device',
                pool_id=pool_id,
                host=self.host
            ),
            topic=self.topic
        )

    def pool_destroyed(self, pool_id):
        return self.call(
            self.context,
            self.make_msg('pool_destroyed', pool_id=pool_id, host=self.host),
            topic=self.topic
        )

    def plug_vip_port(self, port_id):
        return self.call(
            self.context,
            self.make_msg('plug_vip_port', port_id=port_id, host=self.host),
            topic=self.topic
        )

    def unplug_vip_port(self, port_id):
        return self.call(
            self.context,
            self.make_msg('unplug_vip_port', port_id=port_id, host=self.host),
            topic=self.topic
        )

    def update_pool_stats(self, pool_id, stats):
        return self.call(
            self.context,
            self.make_msg(
                'update_pool_stats',
                pool_id=pool_id,
                stats=stats,
                host=self.host
            ),
            topic=self.topic
        )
