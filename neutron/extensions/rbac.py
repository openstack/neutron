# Copyright (c) 2015 Mirantis, Inc.
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

from neutron_lib.api import extensions as api_extensions
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import base
from neutron.conf import quota
from neutron.db import rbac_db_models
from neutron.quota import resource_registry


class RbacPolicyNotFound(n_exc.NotFound):
    message = _("RBAC policy of type %(object_type)s with ID %(id)s not found")


class RbacPolicyInUse(n_exc.Conflict):
    message = _("RBAC policy on object %(object_id)s cannot be removed "
                "because other objects depend on it.\nDetails: %(details)s")


class DuplicateRbacPolicy(n_exc.Conflict):
    message = _("An RBAC policy already exists with those values.")


class RbacPolicyInitError(n_exc.PolicyInitError):
    message = _("Failed to create RBAC policy on object %(object_id)s "
                "because %(reason)s.")


def convert_valid_object_type(otype):
    normalized = otype.strip().lower()
    if normalized in rbac_db_models.get_type_model_map():
        return normalized
    msg = _("'%s' is not a valid RBAC object type") % otype
    raise n_exc.InvalidInput(error_message=msg)


RESOURCE_NAME = 'rbac_policy'
RESOURCE_COLLECTION = 'rbac_policies'

RESOURCE_ATTRIBUTE_MAP = {
    RESOURCE_COLLECTION: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True, 'primary_key': True,
               'is_filter': True},
        'object_type': {'allow_post': True, 'allow_put': False,
                        'convert_to': convert_valid_object_type,
                        'is_visible': True, 'default': None,
                        'is_filter': True,
                        'enforce_policy': True},
        'object_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:uuid': None},
                      'is_visible': True, 'enforce_policy': True,
                      'is_filter': True},
        'target_tenant': {'allow_post': True, 'allow_put': True,
                          'validate': {
                              'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                          'is_visible': True, 'enforce_policy': True,
                          'is_filter': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {
                          'type:string': db_const.PROJECT_ID_FIELD_SIZE},
                      'required_by_policy': True, 'is_visible': True,
                      'is_filter': True},
        'action': {'allow_post': True, 'allow_put': False,
                   # action depends on type so validation has to occur in
                   # the extension
                   'validate': {
                       'type:string': db_const.DESCRIPTION_FIELD_SIZE},
                   # we set enforce_policy so operators can define policies
                   # that restrict actions
                   'is_visible': True, 'enforce_policy': True,
                   'is_filter': True}
    }
}

# Register the configuration options
quota.register_quota_opts(quota.rbac_quota_opts)


class Rbac(api_extensions.ExtensionDescriptor):
    """RBAC policy support."""

    @classmethod
    def get_name(cls):
        return "RBAC Policies"

    @classmethod
    def get_alias(cls):
        return 'rbac-policies'

    @classmethod
    def get_description(cls):
        return ("Allows creation and modification of policies that control "
                "tenant access to resources.")

    @classmethod
    def get_updated(cls):
        return "2015-06-17T12:15:12-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plugin = directory.get_plugin()
        params = RESOURCE_ATTRIBUTE_MAP['rbac_policies']
        collection_name = 'rbac-policies'
        resource_name = 'rbac_policy'
        resource_registry.register_resource_by_name(resource_name)
        controller = base.create_resource(collection_name, resource_name,
                                          plugin, params, allow_bulk=True,
                                          allow_pagination=False,
                                          allow_sorting=True)
        return [extensions.ResourceExtension(collection_name, controller,
                                             attr_map=params)]

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        return {}
