# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Blue Box Group, Inc.
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
# @author: Dustin Lundquist, Blue Box Group

from neutron.plugins.common import constants


class Plugin(object):
    """Wrap a LBaaS v2 plugin and present the v1 interface

    Needs to present the following methods:
    _core_plugin
    _delete_db_member
    _delete_db_pool
    _delete_db_pool_health_monitor
    _delete_db_vip
    _get_resource
    _make_health_monitor_dict
    _make_member_dict
    _make_pool_dict
    _make_vip_dict
    agent_callbacks
    agent_notifiers (field)
    conn
    drivers (field)
    get_lbaas_agent_hosting_pool
    get_lbaas_agents
    get_members
    get_pool
    get_pools
    get_vip
    list_pools_on_lbaas_agent
    populate_vip_graph
    update_pool_health_monitor
    update_pool_stats
    update_status
    """

    agent_notifiers = {}

    def __init__(self, plugin, converter):
        self._plugin = plugin
        self._converter = converter
        self.drivers = {}

    def get_plugin_type(self):
        return constants.LOADBALANCER

    def get_plugin_description(self):
        return "Neutron LoadBalancer Service Compatibility Shim Plugin"

    def _core_plugin(self):
        return self._plugin._core_plugin()

    def _delete_db_vip(self, context, id):
        # TODO(delete load balancer corresponding to given listener id)
        pass

    def _delete_db_pool(self, context, id):
        # TODO(delete load balancer corresponding to given pool id)
        pass

    def _delete_db_member(self, context, id):
        # TODO(how do we pass this on to v2 plugin)
        pass

    def _delete_db_pool_health_monitor(self, context, hm_id, pool_id):
        pass

    def _delete_db_health_monitor(self, context, id):
        pass

    def agent_callbacks():
        pass

    def conn():
        pass

    def get_lbaas_agent_hosting_pool():
        pass

    def get_lbaas_agents():
        pass

    def get_members(self, context, filters=None, fields=None):
        members = self._plugin.get_members(context, filters=filters)
        members = [self._converter.member(member) for member in members]
        # TODO(trim fields)
        return members

    def get_pool(self, context, id, fields=None):
        pool = self._plugin.get_pool(context, id)
        pool = self._converter.pool(pool)
        # TODO(trim fields)
        return pool

    def get_pools(self, context, filters=None, fields=None):
        pools = self._plugin.get_pools(context, filters=filters)
        pools = [self._converter.pool(pool) for pool in pools]
        # TODO(trim fields)
        return pools

    def get_vip(self, context, id, fields=None):
        listener = self._pool.get_listener(context, id)
        vip = self._converter.listener_to_vip(listener)
        # TODO(trim fields)
        return vip

    def list_pools_on_lbaas_agent():
        pass

    def populate_vip_graph(self, context, vip):
        pool = self.get_pool(context, vip['pool_id'])

        vip['pool'] = pool
        vip['members'] = [self.get_members(context, member_id)
                          for member_id in pool['members']]
        vip['health_monitors'] = [self.get_health_monitor(context, hm_id)
                                  for hm_id in pool['health_monitors']]

        return vip

    def update_pool_health_monitor():
        pass

    def update_pool_stats():
        pass

    def update_status(self, context, model, id, status,
                      status_description=None):
        pass
