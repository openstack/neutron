# Copyright (c) 2015 Taturiello Consulting, Meh.
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

from neutron_lib.api import attributes
from neutron_lib.api import converters
from neutron_lib.db import constants as db_const
from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_utils import importutils
import pecan
from pecan import request

from neutron._i18n import _
from neutron.pecan_wsgi.controllers import utils
from neutron.quota import resource_registry

RESOURCE_NAME = "quota"
PROJECT_ID_ATTR = {'project_id':
                   {'allow_post': False,
                    'allow_put': False,
                    'required_by_policy': True,
                    'validate': {'type:string':
                                 db_const.PROJECT_ID_FIELD_SIZE},
                    'is_visible': True}}


class QuotasController(utils.NeutronPecanController):

    def __init__(self):
        self._driver = importutils.import_class(
            cfg.CONF.QUOTAS.quota_driver
        )
        super().__init__(
            "%ss" % RESOURCE_NAME, RESOURCE_NAME)

    def _check_admin(self, context,
                     reason=_("Only admin can view or configure quota")):
        if not context.is_admin:
            raise n_exc.AdminRequired(reason=reason)

    @utils.expose()
    def _lookup(self, project_id, *remainder):
        return QuotaController(self._driver, project_id), remainder

    @utils.expose(generic=True)
    def index(self):
        neutron_context = request.context.get('neutron_context')
        # FIXME(salv-orlando): There shouldn't be any need to do this explicit
        # check. However some behaviours from the "old" extension have
        # been temporarily carried over here
        self._check_admin(neutron_context)
        # TODO(salv-orlando): proper plurals management
        return {self.collection:
                self._driver.get_all_quotas(
                    neutron_context,
                    resource_registry.get_all_resources())}

    @utils.when(index, method='POST')
    @utils.when(index, method='PUT')
    @utils.when(index, method='DELETE')
    def not_supported(self):
        pecan.abort(405)


class QuotaController(utils.NeutronPecanController):

    def __init__(self, _driver, project_id):
        self._driver = _driver
        self._project_id = project_id

        super().__init__(
            "%ss" % RESOURCE_NAME, RESOURCE_NAME)

        # Ensure limits for all registered resources are returned
        attr_dict = attributes.RESOURCES[self.collection]
        for quota_resource in resource_registry.get_all_resources().keys():
            attr_dict[quota_resource] = {
                'allow_post': False,
                'allow_put': True,
                'convert_to': converters.convert_to_int,
                'validate': {
                    'type:range': [-1, db_const.DB_INTEGER_MAX_VALUE]},
                'is_visible': True}
        # The quota resource must always declare a project_id attribute,
        # otherwise the attribute will be stripped off when generating the
        # response
        attr_dict.update(PROJECT_ID_ATTR)

    @utils.expose(generic=True)
    def index(self):
        return get_project_quotas(self._project_id, self._driver)

    @utils.when(index, method='PUT')
    def put(self, *args, **kwargs):
        neutron_context = request.context.get('neutron_context')
        # For put requests there's always going to be a single element
        quota_data = request.context['resources'][0]
        for key, value in quota_data.items():
            self._driver.update_quota_limit(
                neutron_context, self._project_id, key, value)
        return get_project_quotas(self._project_id, self._driver)

    @utils.when_delete(index)
    def delete(self):
        neutron_context = request.context.get('neutron_context')
        self._driver.delete_project_quota(neutron_context,
                                         self._project_id)

    @utils.when(index, method='POST')
    def not_supported(self):
        pecan.abort(405)


def get_project_quotas(project_id, driver=None):
    if not driver:
        driver = importutils.import_class(cfg.CONF.QUOTAS.quota_driver)

    neutron_context = request.context.get('neutron_context')
    if project_id == 'tenant':
        # NOTE(salv-orlando): Read the following before the code in order
        # to avoid puking.
        # There is a weird undocumented behaviour of the Neutron quota API
        # as 'tenant' is used as an API action to return the identifier
        # of the project in the request context. This is used exclusively
        # for interaction with python-neutronclient and is a possibly
        # unnecessary 'whoami' API endpoint. Pending resolution of this
        # API issue, this controller will just treat the magic string
        # 'tenant' (and only that string) and return the response expected
        # by python-neutronclient
        return {'project': {'project_id': neutron_context.project_id}}
    project_quotas = driver.get_project_quotas(
        neutron_context,
        resource_registry.get_all_resources(),
        project_id)
    project_quotas['project_id'] = project_id
    return {RESOURCE_NAME: project_quotas}
