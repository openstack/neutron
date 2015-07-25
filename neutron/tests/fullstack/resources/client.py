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

import fixtures

from neutron.tests import base


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
        self.addCleanup(delete, data['id'])
        return data

    def create_router(self, tenant_id, name=None):
        resource_type = 'router'

        name = name or base.get_rand_name(prefix=resource_type)
        spec = {'tenant_id': tenant_id, 'name': name}

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

    def add_router_interface(self, router_id, subnet_id):
        body = {'subnet_id': subnet_id}
        self.client.add_interface_router(router=router_id, body=body)
        self.addCleanup(self.client.remove_interface_router,
                        router=router_id, body=body)
