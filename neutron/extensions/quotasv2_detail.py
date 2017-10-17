# Copyright 2017 Intel Corporation.
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
from neutron_lib.api import faults
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from oslo_config import cfg

from neutron._i18n import _
from neutron.api import extensions
from neutron.api.v2 import resource
from neutron.extensions import quotasv2
from neutron.quota import resource_registry


DETAIL_QUOTAS_ACTION = 'details'
RESOURCE_NAME = 'quota'
ALIAS = RESOURCE_NAME + '_' + DETAIL_QUOTAS_ACTION
QUOTA_DRIVER = cfg.CONF.QUOTAS.quota_driver
RESOURCE_COLLECTION = RESOURCE_NAME + "s"
DB_QUOTA_DRIVER = 'neutron.db.quota.driver.DbQuotaDriver'
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {}
}


class DetailQuotaSetsController(quotasv2.QuotaSetsController):

    def _get_detailed_quotas(self, request, tenant_id):
        return self._driver.get_detailed_tenant_quotas(
            request.context,
            resource_registry.get_all_resources(), tenant_id)

    def details(self, request, id):
        if id != request.context.project_id:
            # Check if admin
            if not request.context.is_admin:
                reason = _("Only admin is authorized to access quotas for"
                           " another tenant")
                raise n_exc.AdminRequired(reason=reason)
        return {self._resource_name:
                self._get_detailed_quotas(request, id)}


class Quotasv2_detail(api_extensions.ExtensionDescriptor):
    """Quota details management support."""

    # Ensure new extension is not loaded with old conf driver.
    extensions.register_custom_supported_check(
        ALIAS, lambda: True if QUOTA_DRIVER == DB_QUOTA_DRIVER else False,
        plugin_agnostic=True)

    @classmethod
    def get_name(cls):
        return "Quota details management support"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return 'Expose functions for quotas usage statistics per project'

    @classmethod
    def get_updated(cls):
        return "2017-02-10T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Extension Resources."""
        controller = resource.Resource(
            DetailQuotaSetsController(directory.get_plugin()),
            faults=faults.FAULT_MAP)
        return [extensions.ResourceExtension(
            RESOURCE_COLLECTION,
            controller,
            member_actions={'details': 'GET'},
            collection_actions={'tenant': 'GET'})]

    def get_extended_resources(self, version):
        return EXTENDED_ATTRIBUTES_2_0 if version == "2.0" else {}

    def get_required_extensions(self):
        return ["quotas"]
