# All rights reserved.
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

from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import validators
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions as nexception
from neutron_lib.plugins import directory

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource_helper
from neutron.plugins.common import constants


# Flavor Exceptions
class FlavorNotFound(nexception.NotFound):
    message = _("Flavor %(flavor_id)s could not be found.")


class FlavorInUse(nexception.InUse):
    message = _("Flavor %(flavor_id)s is used by some service instance.")


class ServiceProfileNotFound(nexception.NotFound):
    message = _("Service Profile %(sp_id)s could not be found.")


class ServiceProfileInUse(nexception.InUse):
    message = _("Service Profile %(sp_id)s is used by some service instance.")


class FlavorServiceProfileBindingExists(nexception.Conflict):
    message = _("Service Profile %(sp_id)s is already associated "
                "with flavor %(fl_id)s.")


class FlavorServiceProfileBindingNotFound(nexception.NotFound):
    message = _("Service Profile %(sp_id)s is not associated "
                "with flavor %(fl_id)s.")


class ServiceProfileDriverNotFound(nexception.NotFound):
    message = _("Service Profile driver %(driver)s could not be found.")


class ServiceProfileEmpty(nexception.InvalidInput):
    message = _("Service Profile needs either a driver or metainfo.")


class FlavorDisabled(nexception.ServiceUnavailable):
    message = _("Flavor is not enabled.")


class ServiceProfileDisabled(nexception.ServiceUnavailable):
    message = _("Service Profile is not enabled.")


class InvalidFlavorServiceType(nexception.InvalidInput):
    message = _("Invalid service type %(service_type)s.")


def _validate_flavor_service_type(validate_type, valid_values=None):
    """Ensure requested flavor service type plugin is loaded."""
    if not directory.get_plugin(validate_type):
        raise InvalidFlavorServiceType(service_type=validate_type)

validators.add_validator('validate_flavor_service_type',
                         _validate_flavor_service_type)

FLAVORS = 'flavors'
SERVICE_PROFILES = 'service_profiles'
FLAVORS_PREFIX = ""

RESOURCE_ATTRIBUTE_MAP = {
    FLAVORS: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': db_const.NAME_FIELD_SIZE},
                 'is_visible': True, 'default': ''},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string_or_none':
                                     db_const.LONG_DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
        'service_type': {'allow_post': True, 'allow_put': False,
                         'validate':
                         {'type:validate_flavor_service_type': None},
                         'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'validate': {
                          'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'is_visible': True},
        'service_profiles': {'allow_post': True, 'allow_put': True,
                             'validate': {'type:uuid_list': None},
                             'is_visible': True, 'default': []},
        'enabled': {'allow_post': True, 'allow_put': True,
                    'convert_to': converters.convert_to_boolean_if_not_none,
                    'default': True,
                    'is_visible': True},
    },
    SERVICE_PROFILES: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {'type:string_or_none':
                                     db_const.LONG_DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
        'driver': {'allow_post': True, 'allow_put': True,
                   'validate': {'type:string':
                                db_const.LONG_DESCRIPTION_FIELD_SIZE},
                   'is_visible': True,
                   'default': ''},
        'metainfo': {'allow_post': True, 'allow_put': True,
                     'is_visible': True,
                     'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'validate': {
                          'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'is_visible': True},
        'enabled': {'allow_post': True, 'allow_put': True,
                    'convert_to': converters.convert_to_boolean_if_not_none,
                    'is_visible': True, 'default': True},
    },
}


SUB_RESOURCE_ATTRIBUTE_MAP = {
    'next_providers': {
        'parent': {'collection_name': 'flavors',
                   'member_name': 'flavor'},
        'parameters': {'provider': {'allow_post': False,
                                    'allow_put': False,
                                    'is_visible': True},
                       'driver': {'allow_post': False,
                                  'allow_put': False,
                                  'is_visible': True},
                       'metainfo': {'allow_post': False,
                                    'allow_put': False,
                                    'is_visible': True},
                       'tenant_id': {'allow_post': True, 'allow_put': False,
                                     'required_by_policy': True,
                                     'validate': {
                                         'type:string':
                                             db_const.PROJECT_ID_FIELD_SIZE},
                                     'is_visible': True}}
    },
    'service_profiles': {
        'parent': {'collection_name': 'flavors',
                   'member_name': 'flavor'},
        'parameters': {'id': {'allow_post': True, 'allow_put': False,
                              'validate': {'type:uuid': None},
                              'is_visible': True},
                       'tenant_id': {'allow_post': True, 'allow_put': False,
                                     'required_by_policy': True,
                                     'validate': {
                                         'type:string':
                                             db_const.PROJECT_ID_FIELD_SIZE},
                                     'is_visible': True}}
    }
}


class Flavors(api_extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Neutron Service Flavors"

    @classmethod
    def get_alias(cls):
        return "flavors"

    @classmethod
    def get_description(cls):
        return "Flavor specification for Neutron advanced services"

    @classmethod
    def get_updated(cls):
        return "2015-09-17T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)
        resources = resource_helper.build_resource_info(
            plural_mappings,
            RESOURCE_ATTRIBUTE_MAP,
            constants.FLAVORS)
        plugin = directory.get_plugin(constants.FLAVORS)
        for collection_name in SUB_RESOURCE_ATTRIBUTE_MAP:
            # Special handling needed for sub-resources with 'y' ending
            # (e.g. proxies -> proxy)
            resource_name = collection_name[:-1]
            parent = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get('parent')
            params = SUB_RESOURCE_ATTRIBUTE_MAP[collection_name].get(
                'parameters')

            controller = base.create_resource(collection_name, resource_name,
                                              plugin, params,
                                              allow_bulk=True,
                                              parent=parent)

            resource = extensions.ResourceExtension(
                collection_name,
                controller, parent,
                path_prefix=FLAVORS_PREFIX,
                attr_map=params)
            resources.append(resource)

        return resources

    def update_attributes_map(self, attributes):
        super(Flavors, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}
