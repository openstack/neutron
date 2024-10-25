# Copyright (c) 2019 Red Hat, Inc.
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

import collections

from neutron_lib.api.definitions import expose_l3_conntrack_helper as exposedef
from neutron_lib.api.definitions import l3
from neutron_lib.api.definitions import l3_conntrack_helper as apidef
from neutron_lib.callbacks import registry
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib import exceptions as lib_exc
from neutron_lib.exceptions import l3 as lib_l3_exc
from neutron_lib.objects import exceptions as obj_exc
from neutron_lib.plugins import constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_db import exception as oslo_db_exc

from neutron._i18n import _
from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.handlers import resources_rpc
from neutron.db import db_base_plugin_common
from neutron.extensions import l3_conntrack_helper
from neutron.objects import base as base_obj
from neutron.objects import conntrack_helper as cth
from neutron.objects import router
from neutron.services.conntrack_helper.common import exceptions as cth_exc


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class Plugin(l3_conntrack_helper.ConntrackHelperPluginBase):
    """Implementation of the Neutron Conntrack Helper Service Plugin.

    This class implements a Conntrack Helper plugin.
    """

    required_service_plugins = [l3.ROUTER]

    supported_extension_aliases = [apidef.ALIAS, exposedef.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True
    __filter_validation_support = True

    def __init__(self):
        super().__init__()
        self.push_api = resources_rpc.ResourcesPushRpcApi()
        self.l3_plugin = directory.get_plugin(constants.L3)
        self.core_plugin = directory.get_plugin()

        # Option allowed_conntrack_helpers is a list of key, value pairs.
        # The list can contain same key (conntrack helper module) multiple
        # times with a different value (protocol). Merge to a dictonary
        # with key (conntrack helper) and values (protocols) as a list.
        self.constraints = collections.defaultdict(list)
        for x in cfg.CONF.allowed_conntrack_helpers:
            self.constraints[next(iter(x.keys()))].append(
                next(iter(x.values())))

    @staticmethod
    @resource_extend.extends([l3.ROUTERS])
    def _extend_router_dict(result_dict, db):
        fields = [apidef.PROTOCOL, apidef.PORT, apidef.HELPER]
        result_dict[apidef.COLLECTION_NAME] = []
        if db.conntrack_helpers:
            conntack_helper_result = []
            for conntack_helper in db.conntrack_helpers:
                cth_dict = cth.ConntrackHelper.modify_fields_from_db(
                    conntack_helper)
                for key in list(cth_dict.keys()):
                    if key not in fields:
                        cth_dict.pop(key)
                conntack_helper_result.append(cth_dict)
            result_dict[apidef.COLLECTION_NAME] = conntack_helper_result
        return result_dict

    def get_router(self, context, router_id, fields=None):
        router_obj = router.Router.get_object(context, id=router_id)
        if not router_obj:
            raise lib_l3_exc.RouterNotFound(router_id=router_id)
        return router_obj

    def _find_existing_conntrack_helper(self, context, router_id,
                                        conntrack_helper):
        # Because the session had been flushed by NeutronDbObjectDuplicateEntry
        # so if we want to use the context to get another db queries, we need
        # to rollback first.
        context.session.rollback()
        param = {'router_id': router_id,
                 'protocol': conntrack_helper['protocol'],
                 'port': conntrack_helper['port'],
                 'helper': conntrack_helper['helper']}
        objs = cth.ConntrackHelper.get_objects(context, **param)
        if objs:
            return (objs[0], param)

    def _get_conntrack_helper(self, context, id):
        cth_obj = cth.ConntrackHelper.get_object(context, id=id)
        if not cth_obj:
            raise cth_exc.ConntrackHelperNotFound(id=id)
        return cth_obj

    def _check_conntrack_helper_constraints(self, cth_obj):
        if cth_obj.helper not in self.constraints:
            raise cth_exc.ConntrackHelperNotAllowed(helper=cth_obj.helper)
        if cth_obj.protocol not in self.constraints[cth_obj.helper]:
            raise cth_exc.InvalidProtocolForHelper(
                helper=cth_obj.helper, protocol=cth_obj.protocol,
                supported_protocols=', '.join(
                    self.constraints[cth_obj.helper]))

    @db_base_plugin_common.convert_result_to_dict
    def create_router_conntrack_helper(self, context, router_id,
                                       conntrack_helper):
        conntrack_helper = conntrack_helper.get(apidef.RESOURCE_NAME)
        conntrack_helper['router_id'] = router_id
        cth_obj = cth.ConntrackHelper(context, **conntrack_helper)
        self._check_conntrack_helper_constraints(cth_obj)
        try:
            with db_api.CONTEXT_WRITER.using(context):
                # If this get_router does not raise an exception, a router
                # with router_id exists.
                self.get_router(context, router_id)
                cth_obj.create()
        except obj_exc.NeutronDbObjectDuplicateEntry:
            (__, conflict_params) = self._find_existing_conntrack_helper(
                context, router_id, cth_obj.to_dict())
            message = _("A duplicate conntrack helper entry with same "
                        "attributes already exists, conflicting values "
                        "are %s") % conflict_params
            raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                     msg=message)
        self.push_api.push(context, [cth_obj], rpc_events.CREATED)
        return cth_obj

    @db_base_plugin_common.convert_result_to_dict
    def update_router_conntrack_helper(self, context, id, router_id,
                                       conntrack_helper):
        conntrack_helper = conntrack_helper.get(apidef.RESOURCE_NAME)
        try:
            with db_api.CONTEXT_WRITER.using(context):
                cth_obj = self._get_conntrack_helper(context, id)
                cth_obj.update_fields(conntrack_helper, reset_changes=True)
                self._check_conntrack_helper_constraints(cth_obj)
                cth_obj.update()
        except oslo_db_exc.DBDuplicateEntry:
            (__, conflict_params) = self._find_existing_conntrack_helper(
                context, cth_obj.router_id, cth_obj.to_dict())
            message = _("A duplicate conntrack helper entry with same "
                        "attributes already exists, conflicting values "
                        "are %s") % conflict_params
            raise lib_exc.BadRequest(resource=apidef.RESOURCE_NAME,
                                     msg=message)
        self.push_api.push(context, [cth_obj], rpc_events.UPDATED)
        return cth_obj

    @db_base_plugin_common.make_result_with_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_router_conntrack_helper(self, context, id, router_id, fields=None):
        return self._get_conntrack_helper(context, id)

    @db_base_plugin_common.make_result_with_fields
    @db_base_plugin_common.convert_result_to_dict
    def get_router_conntrack_helpers(self, context, router_id=None,
                                     filters=None, fields=None, sorts=None,
                                     limit=None, marker=None,
                                     page_reverse=False):
        filters = filters or {}
        pager = base_obj.Pager(sorts, limit, page_reverse, marker)
        return cth.ConntrackHelper.get_objects(context, _pager=pager,
                                               router_id=router_id, **filters)

    def delete_router_conntrack_helper(self, context, id, router_id):
        cth_obj = self._get_conntrack_helper(context, id)
        with db_api.CONTEXT_WRITER.using(context):
            cth_obj.delete()
        self.push_api.push(context, [cth_obj], rpc_events.DELETED)
