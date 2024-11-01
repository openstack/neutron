# Copyright 2012 OpenStack Foundation.
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

from neutron_lib.api.definitions import servicetype as svctype_apidef
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from oslo_utils import uuidutils

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.db import servicetype_db
from neutron import neutron_plugin_base_v2


RESOURCE_NAME = "dummy"
COLLECTION_NAME = "%ss" % RESOURCE_NAME
DUMMY_SERVICE_TYPE = "DUMMY"
DUMMY_SERVICE_WITH_REQUIRE_TYPE = "DUMMY_REQIURE"

# Attribute Map for dummy resource
RESOURCE_ATTRIBUTE_MAP = {
    COLLECTION_NAME: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'service_type': {'allow_post': True,
                         'allow_put': False,
                         'validate': {'type:servicetype_ref': None},
                         'is_visible': True,
                         'default': None}
    }
}


class Dummy:

    @classmethod
    def get_name(cls):
        return RESOURCE_NAME

    @classmethod
    def get_alias(cls):
        return RESOURCE_NAME

    @classmethod
    def get_description(cls):
        return "Dummy stuff"

    @classmethod
    def get_updated(cls):
        return "2012-11-20T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Extended Resource for dummy management."""
        dummy_inst = directory.get_plugin(DUMMY_SERVICE_TYPE)
        controller = base.create_resource(
            COLLECTION_NAME, RESOURCE_NAME, dummy_inst,
            RESOURCE_ATTRIBUTE_MAP[COLLECTION_NAME])
        return [extensions.ResourceExtension(COLLECTION_NAME,
                                             controller)]


class DummyServicePlugin(service_base.ServicePluginBase):
    """This is a simple plugin for managing instances of a fictional 'dummy'
        service. This plugin is provided as a proof-of-concept of how
        advanced service might leverage the service type extension.
        Ideally, instances of real advanced services, such as firewall
        or VPN will adopt a similar solution.
    """

    supported_extension_aliases = [RESOURCE_NAME, svctype_apidef.ALIAS]
    path_prefix = "/dummy_svc"
    agent_notifiers = {RESOURCE_NAME: 'dummy_agent_notifier'}

    def __init__(self):
        self.svctype_mgr = servicetype_db.ServiceTypeManager.get_instance()
        self.dummys = {}

    @classmethod
    def get_plugin_type(cls):
        return DUMMY_SERVICE_TYPE

    def get_plugin_description(self):
        return "Neutron Dummy Service Plugin"

    def get_dummys(self, context, filters, fields):
        return self.dummys.values()

    def get_dummy(self, context, id, fields):
        try:
            return self.dummys[id]
        except KeyError:
            raise exceptions.NotFound()

    def create_dummy(self, context, dummy):
        d = dummy[RESOURCE_NAME]
        d['id'] = uuidutils.generate_uuid()
        self.dummys[d['id']] = d
        self.svctype_mgr.increase_service_type_refcount(context,
                                                        d['service_type'])
        return d

    def update_dummy(self, context, id, dummy):
        pass

    def delete_dummy(self, context, id):
        try:
            svc_type_id = self.dummys[id]['service_type']
            del self.dummys[id]
            self.svctype_mgr.decrease_service_type_refcount(context,
                                                            svc_type_id)
        except KeyError:
            raise exceptions.NotFound()


class DummyWithRequireServicePlugin(DummyServicePlugin):
    required_service_plugins = ['dummy']

    @classmethod
    def get_plugin_type(cls):
        return DUMMY_SERVICE_WITH_REQUIRE_TYPE

    def get_plugin_description(self):
        return "Neutron Dummy Service Plugin with requirements"


class DummyCorePluginWithoutDatastore(
        neutron_plugin_base_v2.NeutronPluginBaseV2):
    def create_subnet(self, context, subnet):
        pass

    def update_subnet(self, context, id, subnet):
        pass

    def get_subnet(self, context, id, fields=None):
        pass

    def get_subnets(self, context, filters=None, fields=None,
                    sorts=None, limit=None, marker=None, page_reverse=False):
        pass

    def delete_subnet(self, context, id):
        pass

    def create_network(self, context, network):
        pass

    def update_network(self, context, id, network):
        pass

    def get_network(self, context, id, fields=None):
        pass

    def get_networks(self, context, filters=None, fields=None,
                     sorts=None, limit=None, marker=None, page_reverse=False):
        pass

    def delete_network(self, context, id):
        pass

    def create_port(self, context, port):
        pass

    def update_port(self, context, id, port):
        pass

    def get_port(self, context, id, fields=None):
        pass

    def get_ports(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None, page_reverse=False):
        pass

    def delete_port(self, context, id):
        pass
