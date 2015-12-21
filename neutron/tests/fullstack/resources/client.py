# Copyright (c) 2015 Thales Services SAS
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
import functools

import fixtures
from neutronclient.common import exceptions

from neutron.extensions import portbindings
from neutron.tests import base


def _safe_method(f):
    @functools.wraps(f)
    def delete(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except exceptions.NotFound:
            pass
    return delete


class ClientFixture(fixtures.Fixture):
    """Manage and cleanup neutron resources."""

    def __init__(self, client):
        super(ClientFixture, self).__init__()
        self.client = client

    def _create_resource(self, resource_type, spec):
        create = getattr(self.client, 'create_%s' % resource_type)
        delete = getattr(self.client, 'delete_%s' % resource_type)

        body = {resource_type: spec}
        resp = create(body=body)
        data = resp[resource_type]
        self.addCleanup(_safe_method(delete), data['id'])
        return data

    def create_router(self, tenant_id, name=None, ha=False):
        resource_type = 'router'

        name = name or base.get_rand_name(prefix=resource_type)
        spec = {'tenant_id': tenant_id, 'name': name, 'ha': ha}

        return self._create_resource(resource_type, spec)

    def create_network(self, tenant_id, name=None):
        resource_type = 'network'

        name = name or base.get_rand_name(prefix=resource_type)
        spec = {'tenant_id': tenant_id, 'name': name}

        return self._create_resource(resource_type, spec)

    def create_subnet(self, tenant_id, network_id,
                      cidr, gateway_ip=None, ip_version=4,
                      name=None, enable_dhcp=True):
        resource_type = 'subnet'

        name = name or base.get_rand_name(prefix=resource_type)
        spec = {'tenant_id': tenant_id, 'network_id': network_id, 'name': name,
                'cidr': cidr, 'ip_version': ip_version,
                'enable_dhcp': enable_dhcp}
        if gateway_ip:
            spec['gateway_ip'] = gateway_ip

        return self._create_resource(resource_type, spec)

    def create_port(self, tenant_id, network_id, hostname, qos_policy_id=None):
        spec = {
            'network_id': network_id,
            'tenant_id': tenant_id,
            portbindings.HOST_ID: hostname,
        }
        if qos_policy_id:
            spec['qos_policy_id'] = qos_policy_id
        return self._create_resource('port', spec)

    def add_router_interface(self, router_id, subnet_id):
        body = {'subnet_id': subnet_id}
        self.client.add_interface_router(router=router_id, body=body)
        self.addCleanup(_safe_method(self.client.remove_interface_router),
                        router=router_id, body=body)

    def create_qos_policy(self, tenant_id, name, description, shared):
        policy = self.client.create_qos_policy(
            body={'policy': {'name': name,
                             'description': description,
                             'shared': shared,
                             'tenant_id': tenant_id}})

        def detach_and_delete_policy():
            qos_policy_id = policy['policy']['id']
            ports_with_policy = self.client.list_ports(
                qos_policy_id=qos_policy_id)['ports']
            for port in ports_with_policy:
                self.client.update_port(
                    port['id'],
                    body={'port': {'qos_policy_id': None}})
            self.client.delete_qos_policy(qos_policy_id)

        # NOTE: We'll need to add support for detaching from network once
        # create_network() supports qos_policy_id.
        self.addCleanup(_safe_method(detach_and_delete_policy))

        return policy['policy']

    def create_bandwidth_limit_rule(self, tenant_id, qos_policy_id, limit=None,
                                    burst=None):
        rule = {'tenant_id': tenant_id}
        if limit:
            rule['max_kbps'] = limit
        if burst:
            rule['max_burst_kbps'] = burst
        rule = self.client.create_bandwidth_limit_rule(
            policy=qos_policy_id,
            body={'bandwidth_limit_rule': rule})

        self.addCleanup(_safe_method(self.client.delete_bandwidth_limit_rule),
                        rule['bandwidth_limit_rule']['id'],
                        qos_policy_id)

        return rule['bandwidth_limit_rule']
