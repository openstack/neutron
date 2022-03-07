# Copyright 2011 OpenStack Foundation.
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

from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import faults
from neutron_lib.db import constants as const
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_utils import importutils
import webob

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource
from neutron import policy
from neutron import quota
from neutron.quota import resource_registry
from neutron import wsgi


DEFAULT_QUOTAS_ACTION = 'default'
RESOURCE_NAME = 'quota'
RESOURCE_COLLECTION = RESOURCE_NAME + "s"
QUOTAS = quota.QUOTAS
DB_QUOTA_DRIVER = 'neutron.db.quota.driver.DbQuotaDriver'
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {}
}


def validate_policy(context, policy_name):
    policy.init()
    policy.enforce(context,
                   policy_name,
                   target={'project_id': context.project_id},
                   plugin=None)


class QuotaSetsController(wsgi.Controller):

    def __init__(self, plugin):
        self._resource_name = RESOURCE_NAME
        self._plugin = plugin
        self._driver = importutils.import_class(
            cfg.CONF.QUOTAS.quota_driver
        )
        self._update_extended_attributes = True

    def _update_attributes(self):
        for quota_resource in resource_registry.get_all_resources().keys():
            attr_dict = EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION]
            attr_dict[quota_resource] = {
                'allow_post': False,
                'allow_put': True,
                'convert_to': converters.convert_to_int,
                'validate': {'type:range': [-1, const.DB_INTEGER_MAX_VALUE]},
                'is_visible': True}
        self._update_extended_attributes = False

    def _get_quotas(self, request, tenant_id):
        return self._driver.get_tenant_quotas(
            request.context,
            resource_registry.get_all_resources(),
            tenant_id)

    def default(self, request, id):
        context = request.context
        if id != context.tenant_id:
            validate_policy(context, "get_quota")
        return {self._resource_name: self._driver.get_default_quotas(
                   context=context,
                   resources=resource_registry.get_all_resources(),
                   tenant_id=id)}

    def create(self, request, body=None):
        msg = _('POST requests are not supported on this resource.')
        raise webob.exc.HTTPNotImplemented(msg)

    def index(self, request):
        context = request.context
        validate_policy(context, "get_quota")
        return {self._resource_name + "s":
                self._driver.get_all_quotas(
                    context, resource_registry.get_all_resources())}

    def tenant(self, request):
        """Retrieve the tenant info in context."""
        context = request.context
        if not context.tenant_id:
            raise exceptions.QuotaMissingTenant()
        return {'tenant': {'tenant_id': context.tenant_id}}

    def show(self, request, id):
        if id != request.context.tenant_id:
            validate_policy(request.context, "get_quota")
        return {self._resource_name: self._get_quotas(request, id)}

    def delete(self, request, id):
        validate_policy(request.context, "delete_quota")
        self._driver.delete_tenant_quota(request.context, id)

    def update(self, request, id, body=None):
        validate_policy(request.context, "update_quota")
        if self._update_extended_attributes:
            self._update_attributes()
        body = base.Controller.prepare_request_body(
            request.context, body, False, self._resource_name,
            EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION])
        for key, value in body[self._resource_name].items():
            self._driver.update_quota_limit(request.context, id, key, value)
        return {self._resource_name: self._get_quotas(request, id)}


class Quotasv2(api_extensions.ExtensionDescriptor):
    """Quotas management support."""

    extensions.register_custom_supported_check(
        RESOURCE_COLLECTION, lambda: True, plugin_agnostic=True)

    @classmethod
    def get_name(cls):
        return "Quota management support"

    @classmethod
    def get_alias(cls):
        return RESOURCE_COLLECTION

    @classmethod
    def get_description(cls):
        description = 'Expose functions for quotas management'
        if cfg.CONF.QUOTAS.quota_driver == DB_QUOTA_DRIVER:
            description += ' per tenant'
        return description

    @classmethod
    def get_updated(cls):
        return "2012-07-29T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        controller = resource.Resource(
            QuotaSetsController(directory.get_plugin()),
            faults=faults.FAULT_MAP)
        return [extensions.ResourceExtension(
            Quotasv2.get_alias(),
            controller,
            member_actions={DEFAULT_QUOTAS_ACTION: 'GET'},
            collection_actions={'tenant': 'GET'})]

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
