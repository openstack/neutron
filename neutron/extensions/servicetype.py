# Copyright 2013 OpenStack Foundation.
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

from oslo_log import log as logging

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import base
from neutron.db import servicetype_db

LOG = logging.getLogger(__name__)

RESOURCE_NAME = "service_provider"
COLLECTION_NAME = "%ss" % RESOURCE_NAME
SERVICE_ATTR = 'service_type'
PLUGIN_ATTR = 'plugin'
DRIVER_ATTR = 'driver'
EXT_ALIAS = 'service-type'

# Attribute Map for Service Provider Resource
# Allow read-only access
RESOURCE_ATTRIBUTE_MAP = {
    COLLECTION_NAME: {
        'service_type': {'allow_post': False, 'allow_put': False,
                         'is_visible': True},
        'name': {'allow_post': False, 'allow_put': False,
                 'is_visible': True},
        'default': {'allow_post': False, 'allow_put': False,
                    'is_visible': True},
    }
}


class Servicetype(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return _("Neutron Service Type Management")

    @classmethod
    def get_alias(cls):
        return EXT_ALIAS

    @classmethod
    def get_description(cls):
        return _("API for retrieving service providers for "
                 "Neutron advanced services")

    @classmethod
    def get_updated(cls):
        return "2013-01-20T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Extended Resource for service type management."""
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        attributes.PLURALS.update(dict(my_plurals))
        attr_map = RESOURCE_ATTRIBUTE_MAP[COLLECTION_NAME]
        collection_name = COLLECTION_NAME.replace('_', '-')
        controller = base.create_resource(
            collection_name,
            RESOURCE_NAME,
            servicetype_db.ServiceTypeManager.get_instance(),
            attr_map)
        return [extensions.ResourceExtension(collection_name,
                                             controller,
                                             attr_map=attr_map)]

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
