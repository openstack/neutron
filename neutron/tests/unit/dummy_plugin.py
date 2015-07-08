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

from oslo_utils import uuidutils

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.common import exceptions
from neutron.db import servicetype_db
from neutron.extensions import servicetype
from neutron import manager
from neutron.plugins.common import constants
from neutron.services import service_base


RESOURCE_NAME = "dummy"
COLLECTION_NAME = "%ss" % RESOURCE_NAME

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


class Dummy(object):

    @classmethod
    def get_name(cls):
        return "dummy"

    @classmethod
    def get_alias(cls):
        return "dummy"

    @classmethod
    def get_description(cls):
        return "Dummy stuff"

    @classmethod
    def get_updated(cls):
        return "2012-11-20T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Extended Resource for dummy management."""
        n_mgr = manager.NeutronManager.get_instance()
        dummy_inst = n_mgr.get_service_plugins()['DUMMY']
        controller = base.create_resource(
            COLLECTION_NAME, RESOURCE_NAME, dummy_inst,
            RESOURCE_ATTRIBUTE_MAP[COLLECTION_NAME])
        return [extensions.ResourceExtension(COLLECTION_NAME,
                                             controller)]


class DummyServicePlugin(service_base.ServicePluginBase):
    """This is a simple plugin for managing instantes of a fictional 'dummy'
        service. This plugin is provided as a proof-of-concept of how
        advanced service might leverage the service type extension.
        Ideally, instances of real advanced services, such as load balancing
        or VPN will adopt a similar solution.
    """

    supported_extension_aliases = ['dummy', servicetype.EXT_ALIAS]
    path_prefix = "/dummy_svc"
    agent_notifiers = {'dummy': 'dummy_agent_notifier'}

    def __init__(self):
        self.svctype_mgr = servicetype_db.ServiceTypeManager.get_instance()
        self.dummys = {}

    def get_plugin_type(self):
        return constants.DUMMY

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
        d = dummy['dummy']
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
