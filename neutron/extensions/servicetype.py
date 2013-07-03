# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
#
#    @author: Salvatore Orlando, VMware
#

from neutron.api import extensions
from neutron.api.v2 import attributes
from neutron.api.v2 import base
from neutron import context
from neutron.db import servicetype_db
from neutron import manager
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants


LOG = logging.getLogger(__name__)

RESOURCE_NAME = "service_type"
COLLECTION_NAME = "%ss" % RESOURCE_NAME
SERVICE_ATTR = 'service_class'
PLUGIN_ATTR = 'plugin'
DRIVER_ATTR = 'driver'
EXT_ALIAS = 'service-type'

# Attribute Map for Service Type Resource
RESOURCE_ATTRIBUTE_MAP = {
    COLLECTION_NAME: {
        'id': {'allow_post': False, 'allow_put': False,
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'validate': {'type:string': None},
                 'is_visible': True, 'default': ''},
        'default': {'allow_post': False, 'allow_put': False,
                    'is_visible': True},
        #TODO(salvatore-orlando): Service types should not have ownership
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'num_instances': {'allow_post': False, 'allow_put': False,
                          'is_visible': True},
        'service_definitions': {'allow_post': True, 'allow_put': True,
                                'is_visible': True, 'default': None,
                                'validate': {'type:service_definitions':
                                             None}}
    }
}


def set_default_svctype_id(original_id):
    if not original_id:
        svctype_mgr = servicetype_db.ServiceTypeManager.get_instance()
        # Fetch default service type - it must exist
        res = svctype_mgr.get_service_types(context.get_admin_context(),
                                            filters={'default': [True]})
        return res[0]['id']
    return original_id


def _validate_servicetype_ref(data, valid_values=None):
    """Verify the service type id exists."""
    svc_type_id = data
    svctype_mgr = servicetype_db.ServiceTypeManager.get_instance()
    try:
        svctype_mgr.get_service_type(context.get_admin_context(),
                                     svc_type_id)
    except servicetype_db.ServiceTypeNotFound:
        return _("The service type '%s' does not exist") % svc_type_id


def _validate_service_defs(data, valid_values=None):
    """Validate the list of service definitions."""
    try:
        if not data:
            return _("No service type definition was provided. At least a "
                     "service type definition must be provided")
        f_name = _validate_service_defs.__name__
        for svc_def in data:
            try:
                # Do a copy of the original object so we can easily
                # pop out stuff from it
                svc_def_copy = svc_def.copy()
                try:
                    svc_name = svc_def_copy.pop(SERVICE_ATTR)
                    plugin_name = svc_def_copy.pop(PLUGIN_ATTR)
                except KeyError:
                    msg = (_("Required attributes missing in service "
                             "definition: %s") % svc_def)
                    LOG.error(_("%(f_name)s: %(msg)s"),
                              {'f_name': f_name, 'msg': msg})
                    return msg
                # Validate 'service' attribute
                if svc_name not in constants.ALLOWED_SERVICES:
                    msg = (_("Service name '%s' unspecified "
                             "or invalid") % svc_name)
                    LOG.error(_("%(f_name)s: %(msg)s"),
                              {'f_name': f_name, 'msg': msg})
                    return msg
                # Validate 'plugin' attribute
                if not plugin_name:
                    msg = (_("Plugin name not specified in "
                             "service definition %s") % svc_def)
                    LOG.error(_("%(f_name)s: %(msg)s"),
                              {'f_name': f_name, 'msg': msg})
                    return msg
                # TODO(salvatore-orlando): This code will need to change when
                # multiple plugins for each adv service will be supported
                svc_plugin = manager.NeutronManager.get_service_plugins().get(
                    svc_name)
                if not svc_plugin:
                    msg = _("No plugin for service '%s'") % svc_name
                    LOG.error(_("%(f_name)s: %(msg)s"),
                              {'f_name': f_name, 'msg': msg})
                    return msg
                if svc_plugin.get_plugin_name() != plugin_name:
                    msg = _("Plugin name '%s' is not correct ") % plugin_name
                    LOG.error(_("%(f_name)s: %(msg)s"),
                              {'f_name': f_name, 'msg': msg})
                    return msg
                # Validate 'driver' attribute (just check it's a string)
                # FIXME(salvatore-orlando): This should be a list
                # Note: using get() instead of pop() as pop raises if the
                # key is not found, which might happen for the driver
                driver = svc_def_copy.get(DRIVER_ATTR)
                if driver:
                    msg = attributes._validate_string(driver,)
                    if msg:
                        return msg
                    del svc_def_copy[DRIVER_ATTR]
                # Anything left - it should be an error
                if svc_def_copy:
                    msg = (_("Unparseable attributes found in "
                             "service definition %s") % svc_def)
                    LOG.error(_("%(f_name)s: %(msg)s"),
                              {'f_name': f_name, 'msg': msg})
                    return msg
            except TypeError:
                LOG.exception(_("Exception while parsing service "
                                "definition:%s"), svc_def)
                msg = (_("Was expecting a dict for service definition, found "
                         "the following: %s") % svc_def)
                LOG.error(_("%(f_name)s: %(msg)s"),
                          {'f_name': f_name, 'msg': msg})
                return msg
    except TypeError:
        return (_("%s: provided data are not iterable") %
                _validate_service_defs.__name__)

attributes.validators['type:service_definitions'] = _validate_service_defs
attributes.validators['type:servicetype_ref'] = _validate_servicetype_ref


class Servicetype(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return _("Neutron Service Type Management")

    @classmethod
    def get_alias(cls):
        return EXT_ALIAS

    @classmethod
    def get_description(cls):
        return _("API for retrieving and managing service types for "
                 "Neutron advanced services")

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/ext/neutron/service-type/api/v1.0"

    @classmethod
    def get_updated(cls):
        return "2013-01-20T00:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Extended Resource for service type management."""
        my_plurals = [(key, key[:-1]) for key in RESOURCE_ATTRIBUTE_MAP.keys()]
        my_plurals.append(('service_definitions', 'service_definition'))
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
            return dict(RESOURCE_ATTRIBUTE_MAP.items())
        else:
            return {}
