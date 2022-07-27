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

import warnings

from neutron_lib.api import converters
from neutron_lib.api import extensions as api_extensions
from neutron_lib.api import faults
from neutron_lib.db import constants as const
from neutron_lib import exceptions
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging
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
DB_QUOTA_DRIVER = cfg.CONF.QUOTAS.quota_driver
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {}
}
LOG = logging.getLogger(__name__)


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
        self._driver = importutils.import_class(cfg.CONF.QUOTAS.quota_driver)()
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

    def _get_quotas(self, request, project_id):
        return self._driver.get_project_quotas(
            request.context,
            resource_registry.get_all_resources(),
            project_id)

    def default(self, request, id):
        context = request.context
        if id != context.project_id:
            validate_policy(context, "get_quota")
        return {self._resource_name:
                self._driver.get_default_quotas(
                    context=context,
                    resources=resource_registry.get_all_resources(),
                    project_id=id)}

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
        """Retrieve the project info in context."""
        warnings.warn(
            '"tenant" Quota API method is deprecated, use "project" instead')
        return self._project(request, 'tenant')

    def project(self, request):
        """Retrieve the project info in context."""
        return self._project(request, 'project')

    @staticmethod
    def _project(request, key):
        """Retrieve the project info in context."""
        context = request.context
        if not context.project_id:
            raise exceptions.QuotaMissingTenant()
        return {key: {key + '_id': context.project_id}}

    def show(self, request, id):
        if id != request.context.project_id:
            validate_policy(request.context, "get_quota")
        return {self._resource_name: self._get_quotas(request, id)}

    def delete(self, request, id):
        validate_policy(request.context, "delete_quota")
        self._driver.delete_project_quota(request.context, id)

    def update(self, request, id, body=None):
        validate_policy(request.context, "update_quota")
        force = body[self._resource_name].pop('force', None)
        check_limit = body[self._resource_name].pop('check_limit', None)
        # NOTE(ralonsoh): these warning messages will be removed once
        # LP#1953170 is completed and Neutron quota engine accepts "--force" or
        # nothing (by default, Neutron quota engine will check the resource
        # usage before setting the quota limit).
        if force is None and check_limit is None:
            warnings.warn('Neutron quota engine will require "--force" '
                          'parameter to set a quota limit without checking '
                          'the resource usage.')
        elif check_limit:
            warnings.warn('"--check-limit" parameter will not be needed in '
                          'Z+. By default, Neutron quota engine will check '
                          'the resource usage before setting a new quota '
                          'limit. Use "--force" to skip this check.')

        if self._update_extended_attributes:
            self._update_attributes()
        try:
            body = base.Controller.prepare_request_body(
                request.context, body, False, self._resource_name,
                EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION])
        except Exception as e:
            LOG.warning(
                "An exception happened while processing the request "
                "body. The exception message is [%s].", e)
            raise e

        if check_limit:
            resources = resource_registry.get_all_resources()
            for resource_name, limit in body[self._resource_name].items():
                resource_usage = self._driver.get_resource_usage(
                    request.context, id, resources, resource_name)
                if resource_usage > limit:
                    msg = ('Quota limit %(limit)s for %(resource)s must be '
                           'greater than or equal to already used '
                           '%(resource_usage)s' %
                           {'limit': limit, 'resource': resource_name,
                            'resource_usage': resource_usage})
                    raise webob.exc.HTTPBadRequest(msg)

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
            description += ' per project'
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
            collection_actions={'tenant': 'GET',
                                'project': 'GET'})]

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
