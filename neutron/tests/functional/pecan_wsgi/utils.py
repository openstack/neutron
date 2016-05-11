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

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import base
from neutron.pecan_wsgi import controllers
from neutron.pecan_wsgi.controllers import utils as pecan_utils


class FakeSingularCollectionExtension(extensions.ExtensionDescriptor):

    COLLECTION = 'topologies'
    RESOURCE = 'topology'

    RAM = {
        COLLECTION: {
            'fake': {'is_visible': True}
        }
    }

    @classmethod
    def get_name(cls):
        return ""

    @classmethod
    def get_alias(cls):
        return "fake-sc"

    @classmethod
    def get_description(cls):
        return ""

    @classmethod
    def get_updated(cls):
        return "2099-07-23T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return self.RAM
        else:
            return {}

    def get_pecan_controllers(self):
        ctrllr = controllers.CollectionsController(
            self.RESOURCE, self.RESOURCE)
        return [pecan_utils.PecanResourceExtension(self.RESOURCE, ctrllr)]


class FakeSingularCollectionPlugin(object):

    supported_extension_aliases = ['fake-sc']

    def get_topology(self, context, id_, fields=None):
        return {'fake': id_}

    def get_topologies(self, context, filters=None, fields=None):
        return [{'fake': 'fake'}]


def create_network(context, plugin):
    return plugin.create_network(
        context,
        {'network':
         {'name': 'pecannet',
          'tenant_id': 'tenid',
          'shared': False,
          'admin_state_up': True,
          'status': 'ACTIVE'}})


def create_subnet(context, plugin, network_id):
    return plugin.create_subnet(
        context,
        {'subnet':
         {'tenant_id': 'tenid',
          'network_id': network_id,
          'name': 'pecansub',
          'ip_version': 4,
          'cidr': '10.20.30.0/24',
          'gateway_ip': '10.20.30.1',
          'enable_dhcp': True,
          'allocation_pools': [
              {'start': '10.20.30.2',
               'end': '10.20.30.254'}],
          'dns_nameservers': [],
          'host_routes': []}})


def create_router(context, l3_plugin):
    return l3_plugin.create_router(
        context,
        {'router':
         {'name': 'pecanrtr',
          'tenant_id': 'tenid',
          'admin_state_up': True}})


class FakeExtension(extensions.ExtensionDescriptor):

    HYPHENATED_RESOURCE = 'meh_meh'
    HYPHENATED_COLLECTION = HYPHENATED_RESOURCE + 's'

    RAM = {
        HYPHENATED_COLLECTION: {
            'fake': {'is_visible': True}
        }
    }

    @classmethod
    def get_name(cls):
        return "fake-ext"

    @classmethod
    def get_alias(cls):
        return "fake-ext"

    @classmethod
    def get_description(cls):
        return ""

    @classmethod
    def get_updated(cls):
        return "meh"

    def get_resources(self):
        collection = self.HYPHENATED_COLLECTION.replace('_', '-')
        params = self.RAM.get(self.HYPHENATED_COLLECTION, {})
        attributes.PLURALS.update({self.HYPHENATED_COLLECTION:
                                   self.HYPHENATED_RESOURCE})
        controller = base.create_resource(
            collection, self.HYPHENATED_RESOURCE, FakePlugin(),
            params, allow_bulk=True, allow_pagination=True,
            allow_sorting=True)
        return [extensions.ResourceExtension(collection, controller,
                                             attr_map=params)]

    def get_extended_resources(self, version):
        if version == "2.0":
            return self.RAM
        else:
            return {}


class FakePlugin(object):

    PLUGIN_TYPE = 'fake-ext-plugin'
    supported_extension_aliases = ['fake-ext']

    def get_plugin_type(self):
        return self.PLUGIN_TYPE

    def get_meh_meh(self, context, id_, fields=None):
        return {'fake': id_}

    def get_meh_mehs(self, context, filters=None, fields=None):
        return [{'fake': 'fake'}]
