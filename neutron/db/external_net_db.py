# Copyright (c) 2013 OpenStack Foundation.
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

from neutron_lib.api.definitions import external_net as extnet_apidef
from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.db import model_query
from neutron_lib.db import resource_extend
from neutron_lib import exceptions as n_exc
from neutron_lib.exceptions import external_net as extnet_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory

from neutron._i18n import _
from neutron.db import models_v2
from neutron.db import rbac_db_models
from neutron.extensions import rbac as rbac_ext
from neutron.objects import network as net_obj
from neutron.objects import ports as port_obj
from neutron.objects import router as l3_obj


EXTERNAL_NETWORK_RBAC_ACTIONS = {constants.ACCESS_SHARED,
                                 constants.ACCESS_READONLY,
                                 constants.ACCESS_EXTERNAL}


def _network_result_filter_hook(query, filters):
    vals = filters and filters.get(extnet_apidef.EXTERNAL, [])
    if not vals:
        return query
    if vals[0]:
        return query.filter(models_v2.Network.external.has())
    return query.filter(~models_v2.Network.external.has())


def _subnet_result_filter_hook(query, filters):
    vals = filters and filters.get(extnet_apidef.EXTERNAL, [])
    if not vals:
        return query
    if vals[0]:
        return query.filter(models_v2.Subnet.external.has())
    return query.filter(~models_v2.Subnet.external.has())


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class External_net_db_mixin(object):
    """Mixin class to add external network methods to db_base_plugin_v2."""

    def __new__(cls, *args, **kwargs):
        model_query.register_hook(
            models_v2.Network,
            "external_net",
            query_hook=None,
            filter_hook=None,
            result_filters=_network_result_filter_hook,
            rbac_actions=EXTERNAL_NETWORK_RBAC_ACTIONS,
        )
        model_query.register_hook(
            models_v2.Subnet,
            "external_subnet",
            query_hook=None,
            filter_hook=None,
            result_filters=_subnet_result_filter_hook,
            rbac_actions=EXTERNAL_NETWORK_RBAC_ACTIONS,
        )
        return super(External_net_db_mixin, cls).__new__(cls, *args, **kwargs)

    def _network_is_external(self, context, net_id):
        return net_obj.ExternalNetwork.objects_exist(
            context, network_id=net_id)

    @staticmethod
    @resource_extend.extends([net_def.COLLECTION_NAME])
    def _extend_network_dict_l3(network_res, network_db):
        # Comparing with None for converting uuid into bool
        network_res[extnet_apidef.EXTERNAL] = network_db.external is not None
        return network_res

    @staticmethod
    @resource_extend.extends([subnet_def.COLLECTION_NAME])
    def _extend_subnet_dict_l3(subnet_res, subnet_db):
        # Comparing with None for converting uuid into bool
        subnet_res[extnet_apidef.EXTERNAL] = bool(subnet_db.external)
        return subnet_res

    def _process_l3_create(self, context, net_data, req_data):
        external = req_data.get(extnet_apidef.EXTERNAL)
        external_set = validators.is_attr_set(external)

        if not external_set:
            return

        if external:
            net_obj.ExternalNetwork(
                context, network_id=net_data['id']).create()
            net_rbac_args = {'project_id': net_data['tenant_id'],
                             'object_id': net_data['id'],
                             'action': rbac_db_models.ACCESS_EXTERNAL,
                             'target_project': '*'}
            net_obj.NetworkRBAC(context, **net_rbac_args).create()
        net_data[extnet_apidef.EXTERNAL] = external

    def _process_l3_update(self, context, net_data, req_data, allow_all=True):
        new_value = req_data.get(extnet_apidef.EXTERNAL)
        net_id = net_data['id']
        if not validators.is_attr_set(new_value):
            return

        if net_data.get(extnet_apidef.EXTERNAL) == new_value:
            return

        if new_value:
            net_obj.ExternalNetwork(
                context, network_id=net_id).create()
            net_data[extnet_apidef.EXTERNAL] = True
            if allow_all:
                net_rbac_args = {'project_id': net_data['tenant_id'],
                                 'object_id': net_id,
                                 'action': rbac_db_models.ACCESS_EXTERNAL,
                                 'target_project': '*'}
                net_obj.NetworkRBAC(context, **net_rbac_args).create()
        else:
            # must make sure we do not have any external gateway ports
            # (and thus, possible floating IPs) on this network before
            # allow it to be update to external=False
            if port_obj.Port.count(
                    context, network_id=net_data['id'],
                    device_owner=constants.DEVICE_OWNER_ROUTER_GW):
                raise extnet_exc.ExternalNetworkInUse(net_id=net_id)

            net_obj.ExternalNetwork.delete_objects(
                context, network_id=net_id)
            net_obj.NetworkRBAC.delete_objects(
                context, object_id=net_id,
                action=rbac_db_models.ACCESS_EXTERNAL)
            net_data[extnet_apidef.EXTERNAL] = False

    def _process_l3_delete(self, context, network_id):
        l3plugin = directory.get_plugin(plugin_constants.L3)
        if l3plugin:
            l3plugin.delete_disassociated_floatingips(context, network_id)

    @registry.receives(resources.RBAC_POLICY, [events.BEFORE_CREATE])
    def _process_ext_policy_create(self, resource, event, trigger,
                                   payload=None):
        object_type = payload.metadata.get('object_type')
        policy = payload.request_body
        context = payload.context

        if (object_type != 'network' or
                policy['action'] != rbac_db_models.ACCESS_EXTERNAL):
            return
        net = self.get_network(context, policy['object_id'])
        if not context.is_admin and net['tenant_id'] != context.tenant_id:
            msg = _("Only admins can manipulate policies on networks they "
                    "do not own")
            raise n_exc.InvalidInput(error_message=msg)
        if not self._network_is_external(context, policy['object_id']):
            # we automatically convert the network into an external network
            self._process_l3_update(context, net,
                                    {extnet_apidef.EXTERNAL: True},
                                    allow_all=False)

    @registry.receives(resources.RBAC_POLICY, [events.AFTER_DELETE])
    def _process_ext_policy_delete(self, resource, event, trigger,
                                   payload=None):
        object_type = payload.metadata.get('object_type')
        policy = payload.latest_state
        context = payload.context

        if (object_type != 'network' or
                policy['action'] != rbac_db_models.ACCESS_EXTERNAL):
            return
        # If the network still have rbac policies, we should not
        # update external attribute.
        if net_obj.NetworkRBAC.count(context, object_id=policy['object_id'],
                                     action=rbac_db_models.ACCESS_EXTERNAL):
            return
        net = self.get_network(context, policy['object_id'])
        self._process_l3_update(context, net,
                                {extnet_apidef.EXTERNAL: False})

    @registry.receives(resources.RBAC_POLICY, (events.BEFORE_UPDATE,
                                               events.BEFORE_DELETE))
    def _validate_ext_not_in_use_by_tenant(self, resource, event, trigger,
                                           payload=None):
        object_type = payload.metadata.get('object_type')
        policy = payload.latest_state
        context = payload.context

        if (object_type != 'network' or
                policy['action'] != rbac_db_models.ACCESS_EXTERNAL):
            return
        new_project = None
        if event == events.BEFORE_UPDATE:
            new_project = payload.request_body['target_project']
            if new_project == policy['target_project']:
                # nothing to validate if the tenant didn't change
                return

        gw_ports = port_obj.Port.get_gateway_port_ids_by_network(
            context, policy['object_id'])
        if policy['target_project'] != '*':
            filters = {
                'gw_port_id': gw_ports,
                'project_id': policy['target_project']
            }
            # if there is a wildcard entry we can safely proceed without the
            # router lookup because they will have access either way
            if net_obj.NetworkRBAC.count(
                    context, object_id=policy['object_id'],
                    action=rbac_db_models.ACCESS_EXTERNAL, target_project='*'):
                return
            router_exist = l3_obj.Router.objects_exist(context, **filters)
        else:
            # deleting the wildcard is okay as long as the tenants with
            # attached routers have their own entries and the network is
            # not the default external network.
            if net_obj.ExternalNetwork.objects_exist(
                    context, network_id=policy['object_id'], is_default=True):
                msg = _("Default external networks must be shared to "
                        "everyone.")
                raise rbac_ext.RbacPolicyInUse(object_id=policy['object_id'],
                                               details=msg)
            projects = net_obj.NetworkRBAC.get_projects(
                context, object_id=policy['object_id'],
                action=rbac_db_models.ACCESS_EXTERNAL)
            projects_with_entries = [project for project in projects
                                     if project != '*']
            if new_project:
                projects_with_entries.append(new_project)
            router_exist = l3_obj.Router.check_routers_not_owned_by_projects(
                context, gw_ports, projects_with_entries)
        if router_exist:
            msg = _("There are routers attached to this network that "
                    "depend on this policy for access.")
            raise rbac_ext.RbacPolicyInUse(object_id=policy['object_id'],
                                           details=msg)

    @registry.receives(resources.NETWORK, [events.BEFORE_DELETE])
    def _before_network_delete_handler(self, resource, event, trigger,
                                       payload=None):
        self._process_l3_delete(payload.context, payload.resource_id)
