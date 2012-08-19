# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
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

import webob

from quantum.api.v2 import base
from quantum.common import exceptions
from quantum.extensions import extensions
from quantum.extensions import _quotav2_driver as quotav2_driver
from quantum.extensions import _quotav2_model as quotav2_model
from quantum.manager import QuantumManager
from quantum.openstack.common import cfg
from quantum import quota
from quantum import wsgi

RESOURCE_NAME = 'quota'
RESOURCE_COLLECTION = RESOURCE_NAME + "s"
QUOTAS = quota.QUOTAS
DB_QUOTA_DRIVER = 'quantum.extensions._quotav2_driver.DbQuotaDriver'
EXTENDED_ATTRIBUTES_2_0 = {
    RESOURCE_COLLECTION: {}
}

for quota_resource in QUOTAS.resources.iterkeys():
    attr_dict = EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION]
    attr_dict[quota_resource] = {'allow_post': False,
                                 'allow_put': True,
                                 'convert_to': int,
                                 'is_visible': True}


class QuotaSetsController(wsgi.Controller):

    def __init__(self, plugin):
        self._resource_name = RESOURCE_NAME
        self._plugin = plugin

    def _get_body(self, request):
        body = self._deserialize(request.body, request.get_content_type())
        attr_info = EXTENDED_ATTRIBUTES_2_0[RESOURCE_COLLECTION]
        req_body = base.Controller.prepare_request_body(
            request.context, body, False, self._resource_name, attr_info)
        return req_body

    def _get_quotas(self, request, tenant_id):
        values = quotav2_driver.DbQuotaDriver.get_tenant_quotas(
            request.context, QUOTAS.resources, tenant_id)
        return dict((k, v['limit']) for k, v in values.items())

    def create(self, request, body=None):
        raise NotImplementedError()

    def index(self, request):
        context = request.context
        if not context.is_admin:
            raise webob.exc.HTTPForbidden()
        return {self._resource_name + "s":
                quotav2_driver.DbQuotaDriver.get_all_quotas(
                    context, QUOTAS.resources)}

    def tenant(self, request):
        """Retrieve the tenant info in context."""
        context = request.context
        if not context.tenant_id:
            raise webob.exc.HTTPBadRequest('invalid tenant')
        return {'tenant': {'tenant_id': context.tenant_id}}

    def show(self, request, id):
        context = request.context
        tenant_id = id
        if not tenant_id:
            raise webob.exc.HTTPBadRequest('invalid tenant')
        if (tenant_id != context.tenant_id and
            not context.is_admin):
            raise webob.exc.HTTPForbidden()
        return {self._resource_name:
                self._get_quotas(request, tenant_id)}

    def _check_modification_delete_privilege(self, context, tenant_id):
        if not tenant_id:
            raise webob.exc.HTTPBadRequest('invalid tenant')
        if (not context.is_admin):
            raise webob.exc.HTTPForbidden()
        return tenant_id

    def delete(self, request, id):
        tenant_id = id
        tenant_id = self._check_modification_delete_privilege(request.context,
                                                              tenant_id)
        quotav2_driver.DbQuotaDriver.delete_tenant_quota(request.context,
                                                         tenant_id)

    def update(self, request, id):
        tenant_id = id
        tenant_id = self._check_modification_delete_privilege(request.context,
                                                              tenant_id)
        req_body = self._get_body(request)
        for key in req_body[self._resource_name].keys():
            if key in QUOTAS.resources:
                value = int(req_body[self._resource_name][key])
                with request.context.session.begin():
                    tenant_quotas = request.context.session.query(
                        quotav2_model.Quota).filter_by(tenant_id=tenant_id,
                                                       resource=key).all()
                    if not tenant_quotas:
                        quota = quotav2_model.Quota(tenant_id=tenant_id,
                                                    resource=key,
                                                    limit=value)
                        request.context.session.add(quota)
                    else:
                        quota = tenant_quotas[0]
                        quota.update({'limit': value})
        return {self._resource_name: self._get_quotas(request, tenant_id)}


class Quotasv2(object):
    """Quotas management support"""
    @classmethod
    def get_name(cls):
        return "Quotas for each tenant"

    @classmethod
    def get_alias(cls):
        return RESOURCE_COLLECTION

    @classmethod
    def get_description(cls):
        return ("Expose functions for cloud admin to update quotas"
                "for each tenant")

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/network/ext/quotas-sets/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2012-07-29T10:00:00-00:00"

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

    def check_env(self):
        if cfg.CONF.QUOTAS.quota_driver != DB_QUOTA_DRIVER:
            msg = _('quota driver %s is needed.') % DB_QUOTA_DRIVER
            raise exceptions.InvalidExtenstionEnv(reason=msg)

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        controller = QuotaSetsController(QuantumManager.get_plugin())
        return [extensions.ResourceExtension(
            Quotasv2.get_alias(),
            controller,
            collection_actions={'tenant': 'GET'})]
