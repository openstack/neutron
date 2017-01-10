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

from neutron_lib.api import validators
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from neutron_lib.plugins import directory
from sqlalchemy.orm import exc
from sqlalchemy.sql import expression as expr

from neutron._i18n import _
from neutron.api.v2 import attributes
from neutron.callbacks import events
from neutron.callbacks import exceptions as c_exc
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.common import _deprecate
from neutron.db import _utils as db_utils
from neutron.db import db_base_plugin_v2
from neutron.db.models import external_net as ext_net_models
from neutron.db.models import l3 as l3_models
from neutron.db import models_v2
from neutron.db import rbac_db_models as rbac_db
from neutron.extensions import external_net
from neutron.extensions import rbac as rbac_ext


DEVICE_OWNER_ROUTER_GW = constants.DEVICE_OWNER_ROUTER_GW

_deprecate._moved_global('ExternalNetwork', new_module=ext_net_models)


class External_net_db_mixin(object):
    """Mixin class to add external network methods to db_base_plugin_v2."""

    @staticmethod
    def _network_filter_hook(context, original_model, conditions):
        if conditions is not None and not hasattr(conditions, '__iter__'):
            conditions = (conditions, )
        # Apply the external network filter only in non-admin and non-advsvc
        # context
        if db_utils.model_query_scope_is_project(context, original_model):
            # the table will already be joined to the rbac entries for the
            # shared check so we don't need to worry about ensuring that
            rbac_model = original_model.rbac_entries.property.mapper.class_
            tenant_allowed = (
                (rbac_model.action == 'access_as_external') &
                (rbac_model.target_tenant == context.tenant_id) |
                (rbac_model.target_tenant == '*'))
            conditions = expr.or_(tenant_allowed, *conditions)
        return conditions

    def _network_result_filter_hook(self, query, filters):
        vals = filters and filters.get(external_net.EXTERNAL, [])
        if not vals:
            return query
        if vals[0]:
            return query.filter(models_v2.Network.external.has())
        return query.filter(~models_v2.Network.external.has())

    # TODO(salvatore-orlando): Perform this operation without explicitly
    # referring to db_base_plugin_v2, as plugins that do not extend from it
    # might exist in the future
    db_base_plugin_v2.NeutronDbPluginV2.register_model_query_hook(
        models_v2.Network,
        "external_net",
        None,
        '_network_filter_hook',
        '_network_result_filter_hook')

    def _network_is_external(self, context, net_id):
        try:
            context.session.query(
                ext_net_models.ExternalNetwork).filter_by(
                    network_id=net_id).one()
            return True
        except exc.NoResultFound:
            return False

    def _extend_network_dict_l3(self, network_res, network_db):
        # Comparing with None for converting uuid into bool
        network_res[external_net.EXTERNAL] = network_db.external is not None
        return network_res

    # Register dict extend functions for networks
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attributes.NETWORKS, ['_extend_network_dict_l3'])

    def _process_l3_create(self, context, net_data, req_data):
        external = req_data.get(external_net.EXTERNAL)
        external_set = validators.is_attr_set(external)

        if not external_set:
            return

        # TODO(armax): these notifications should switch to *_COMMIT
        # when the event becomes available, as this block is expected
        # to be called within a plugin's session
        if external:
            try:
                registry.notify(
                    resources.EXTERNAL_NETWORK, events.BEFORE_CREATE,
                    self, context=context,
                    request=req_data, network=net_data)
            except c_exc.CallbackFailure as e:
                # raise the underlying exception
                raise e.errors[0].error
            context.session.add(
                ext_net_models.ExternalNetwork(network_id=net_data['id']))
            context.session.add(rbac_db.NetworkRBAC(
                  object_id=net_data['id'], action='access_as_external',
                  target_tenant='*', tenant_id=net_data['tenant_id']))
            registry.notify(
                resources.EXTERNAL_NETWORK, events.AFTER_CREATE,
                self, context=context,
                request=req_data, network=net_data)
        net_data[external_net.EXTERNAL] = external

    def _process_l3_update(self, context, net_data, req_data, allow_all=True):
        try:
            registry.notify(
                resources.EXTERNAL_NETWORK, events.BEFORE_UPDATE,
                self, context=context,
                request=req_data, network=net_data)
        except c_exc.CallbackFailure as e:
            # raise the underlying exception
            raise e.errors[0].error

        new_value = req_data.get(external_net.EXTERNAL)
        net_id = net_data['id']
        if not validators.is_attr_set(new_value):
            return

        if net_data.get(external_net.EXTERNAL) == new_value:
            return

        if new_value:
            context.session.add(
                ext_net_models.ExternalNetwork(network_id=net_id))
            net_data[external_net.EXTERNAL] = True
            if allow_all:
                context.session.add(rbac_db.NetworkRBAC(
                      object_id=net_id, action='access_as_external',
                      target_tenant='*', tenant_id=net_data['tenant_id']))
        else:
            # must make sure we do not have any external gateway ports
            # (and thus, possible floating IPs) on this network before
            # allow it to be update to external=False
            port = context.session.query(models_v2.Port).filter_by(
                device_owner=DEVICE_OWNER_ROUTER_GW,
                network_id=net_data['id']).first()
            if port:
                raise external_net.ExternalNetworkInUse(net_id=net_id)

            for edb in (context.session.query(ext_net_models.ExternalNetwork).
                        filter_by(network_id=net_id)):
                context.session.delete(edb)
            for rbdb in (context.session.query(rbac_db.NetworkRBAC).filter_by(
                         object_id=net_id, action='access_as_external')):
                context.session.delete(rbdb)
            net_data[external_net.EXTERNAL] = False

    def _process_l3_delete(self, context, network_id):
        l3plugin = directory.get_plugin(constants.L3)
        if l3plugin:
            l3plugin.delete_disassociated_floatingips(context, network_id)

    def get_external_network_id(self, context):
        nets = self.get_networks(context, {external_net.EXTERNAL: [True]})
        if len(nets) > 1:
            raise n_exc.TooManyExternalNetworks()
        else:
            return nets[0]['id'] if nets else None

    def _process_ext_policy_create(self, resource, event, trigger, context,
                                   object_type, policy, **kwargs):
        if (object_type != 'network' or
                policy['action'] != 'access_as_external'):
            return
        net = self.get_network(context, policy['object_id'])
        if not context.is_admin and net['tenant_id'] != context.tenant_id:
            msg = _("Only admins can manipulate policies on networks they "
                    "do not own")
            raise n_exc.InvalidInput(error_message=msg)
        if not self._network_is_external(context, policy['object_id']):
            # we automatically convert the network into an external network
            self._process_l3_update(context, net,
                                    {external_net.EXTERNAL: True},
                                    allow_all=False)

    def _validate_ext_not_in_use_by_tenant(self, resource, event, trigger,
                                           context, object_type, policy,
                                           **kwargs):
        if (object_type != 'network' or
                policy['action'] != 'access_as_external'):
            return
        new_tenant = None
        if event == events.BEFORE_UPDATE:
            new_tenant = kwargs['policy_update']['target_tenant']
            if new_tenant == policy['target_tenant']:
                # nothing to validate if the tenant didn't change
                return
        ports = context.session.query(models_v2.Port.id).filter_by(
            device_owner=DEVICE_OWNER_ROUTER_GW,
            network_id=policy['object_id'])
        router = context.session.query(l3_models.Router).filter(
            l3_models.Router.gw_port_id.in_(ports))
        rbac = rbac_db.NetworkRBAC
        if policy['target_tenant'] != '*':
            router = router.filter(
                l3_models.Router.tenant_id == policy['target_tenant'])
            # if there is a wildcard entry we can safely proceed without the
            # router lookup because they will have access either way
            if context.session.query(rbac_db.NetworkRBAC).filter(
                    rbac.object_id == policy['object_id'],
                    rbac.action == 'access_as_external',
                    rbac.target_tenant == '*').count():
                return
        else:
            # deleting the wildcard is okay as long as the tenants with
            # attached routers have their own entries and the network is
            # not the default external network.
            is_default = context.session.query(
                ext_net_models.ExternalNetwork).filter_by(
                    network_id=policy['object_id'], is_default=True).count()
            if is_default:
                msg = _("Default external networks must be shared to "
                        "everyone.")
                raise rbac_ext.RbacPolicyInUse(object_id=policy['object_id'],
                                               details=msg)
            tenants_with_entries = (
                context.session.query(rbac.target_tenant).
                filter(rbac.object_id == policy['object_id'],
                       rbac.action == 'access_as_external',
                       rbac.target_tenant != '*'))
            router = router.filter(
                ~l3_models.Router.tenant_id.in_(tenants_with_entries))
            if new_tenant:
                # if this is an update we also need to ignore any router
                # interfaces that belong to the new target.
                router = router.filter(
                    l3_models.Router.tenant_id != new_tenant)
        if router.count():
            msg = _("There are routers attached to this network that "
                    "depend on this policy for access.")
            raise rbac_ext.RbacPolicyInUse(object_id=policy['object_id'],
                                           details=msg)

    def _register_external_net_rbac_hooks(self):
        registry.subscribe(self._process_ext_policy_create,
                           'rbac-policy', events.BEFORE_CREATE)
        for e in (events.BEFORE_UPDATE, events.BEFORE_DELETE):
            registry.subscribe(self._validate_ext_not_in_use_by_tenant,
                               'rbac-policy', e)

    def __new__(cls, *args, **kwargs):
        new = super(External_net_db_mixin, cls).__new__(cls, *args, **kwargs)
        new._register_external_net_rbac_hooks()
        return new


_deprecate._MovedGlobals()
