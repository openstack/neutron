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


class LBObjectModelConverter(object):
    """Convert LBaaS v2 object model to v1 dicts"""

    def _first_listener(load_balancer):
        return (load_balancer.listeners or [{}])[0]

    def lb_to_vip(self, load_balancer):
        listener = self._first_listener(load_balancer)

        return self.listener_to_vip(listener)

    def listener_to_vip(self, listener):
        res = {'id': listener.id,
               'tenant_id': load_balancer.tenant_id,
               'name': load_balancer.name,
               'description': load_balancer.description,
               'subnet_id': load_balancer.description,
               'address': load_balancer.vip_address,
               'port_id': load_balancer.port_id,
               'protocol_port': listener.protocol_port,
               'protocol': listener.protocol,
               'pool_id': listener.default_pool_id,
               'session_persistence': None,
               'connection_limit': listener.connection_limit,
               'admin_state_up': load_balancer.admin_state_up,
               'status': load_balancer.status,
               'status_description': None}

        # TODO(session_persistance)
        # TODO(status_description)

        return res

    def pool(self, pool):

        res = {'id': pool['id'],
               'tenant_id': pool['tenant_id'],
               'name': pool['name'],
               'description': pool['description'],
               'subnet_id': pool['subnet_id'],
               'protocol': pool['protocol'],
               'vip_id': pool['vip_id'],
               'lb_method': pool['lb_method'],
               'admin_state_up': pool['admin_state_up'],
               'status': pool['status'],
               'status_description': pool['status_description'],
               'provider': ''
               }

        res['members'] = [member.id for member in pool.members]

        # TODO(provider)
        # TODO(health monitors)

        return res

    def member(self, member):

        res = {'id': member['id'],
               'tenant_id': member['tenant_id'],
               'pool_id': member['pool_id'],
               'address': member['address'],
               'protocol_port': member['protocol_port'],
               'weight': member['weight'],
               'admin_state_up': member['admin_state_up'],
               'status': member['status'],
               'status_description': member['status_description']}

        return res
