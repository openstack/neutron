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
from neutron_lib.callbacks import events
from neutron_lib.callbacks import priority_group
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as const
from neutron_lib.db import api as db_api
from neutron_lib.exceptions import l3 as l3_exc
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.plugins import directory
from oslo_config import cfg
from oslo_log import log as logging

from neutron.db import l3_attrs_db
from neutron.objects import router
from neutron.services.l3_router.service_providers import base


LOG = logging.getLogger(__name__)


@registry.has_registry_receivers
class UserDefined(base.L3ServiceProvider):
    ha_support = base.OPTIONAL

    def __init__(self, l3_plugin):
        super().__init__(l3_plugin)
        self._user_defined_provider = __name__ + "." + self.__class__.__name__

    @property
    def _flavor_plugin(self):
        try:
            return self._flavor_plugin_ref
        except AttributeError:
            self._flavor_plugin_ref = directory.get_plugin(
                plugin_constants.FLAVORS)
            return self._flavor_plugin_ref

    def _is_user_defined_provider(self, context, router):
        flavor_id = router.get('flavor_id')
        if flavor_id is None or flavor_id is const.ATTR_NOT_SPECIFIED:
            return False
        flavor = self._flavor_plugin.get_flavor(context, flavor_id)
        provider = self._flavor_plugin.get_flavor_next_provider(
            context, flavor['id'])[0]
        return str(provider['driver']) == self._user_defined_provider

    @registry.receives(resources.ROUTER_CONTROLLER,
                       [events.PRECOMMIT_ADD_ASSOCIATION])
    def _process_router_add_association(self, resource, event, trigger,
                                        payload=None):
        router = payload.states[0]
        context = payload.context
        if not self._is_user_defined_provider(context, router):
            return
        LOG.debug('Got request to associate user defined flavor to router %s',
                  router)

    def _is_ha(self, router):
        ha = router.get('ha')
        if not validators.is_attr_set(ha):
            ha = cfg.CONF.l3_ha
        return ha

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_CREATE],
                       priority_group.PRIORITY_ROUTER_EXTENDED_ATTRIBUTE)
    def _process_precommit_router_create(self, resource, event, trigger,
                                         payload):
        router = payload.latest_state
        context = payload.context
        if not self._is_user_defined_provider(context, router):
            return
        router_db = payload.metadata['router_db']
        is_ha = self._is_ha(router)
        router['ha'] = is_ha
        l3_attrs_db.ExtraAttributesMixin.set_extra_attr_value(router_db,
                                                              'ha', is_ha)

    @registry.receives(resources.ROUTER, [events.AFTER_CREATE])
    def _process_router_create(self, resource, event, trigger, payload=None):
        router = payload.states[0]
        context = payload.context
        if not self._is_user_defined_provider(context, router):
            return
        LOG.debug('Got request to create a user defined flavor router %s',
                  router)

    @registry.receives(resources.ROUTER, [events.AFTER_UPDATE])
    def _process_router_update(self, resource, event, trigger, payload=None):
        original = payload.states[0]
        updated = payload.states[1]
        context = payload.context
        if not self._is_user_defined_provider(context, original):
            # flavor_id attribute is not allowed in router PUTs, so we only
            # need to check the original router
            return
        router_id = payload.resource_id
        LOG.debug('Got request to update a user defined flavor router with id '
                  '%s. Original: %s. Updated: %s', router_id, original,
                  updated)

    @registry.receives(resources.ROUTER, [events.AFTER_DELETE])
    def _process_router_delete(self, resource, event, trigger, payload=None):
        router = payload.states[0]
        context = payload.context
        if not self._is_user_defined_provider(context, router):
            return
        router_id = payload.resource_id
        LOG.debug('Got request to delete a user defined flavor router with ',
                  'id %s:', router_id)

    @registry.receives(resources.ROUTER_INTERFACE, [events.AFTER_CREATE])
    def _process_add_router_interface(self, resource, event, trigger, payload):
        router = payload.states[0]
        context = payload.context
        if not self._is_user_defined_provider(context, router):
            return
        port = payload.metadata['port']
        subnets = payload.metadata['subnets']
        router_interface_info = self.l3plugin._make_router_interface_info(
            router.id, port['tenant_id'], port['id'], port['network_id'],
            subnets[-1]['id'], [subnet['id'] for subnet in subnets])
        LOG.debug('Got request to add interface %s to a user defined flavor '
                  'router with id %s', router_interface_info, router.id)

    @registry.receives(resources.ROUTER_INTERFACE, [events.AFTER_DELETE])
    def _process_remove_router_interface(self, resource, event, trigger,
                                         payload):
        router = payload.states[0]
        context = payload.context
        if not self._is_user_defined_provider(context, router):
            return
        subnet_ids = payload.metadata['subnet_ids']
        LOG.debug('Got request to remove interface to subnets %s from a user '
                  'defined flavor router with id %s', subnet_ids, router.id)

    @registry.receives(resources.FLOATING_IP, [events.AFTER_CREATE])
    def _process_floatingip_create(self, resource, event, trigger, payload):
        context = payload.context
        fip = payload.states[0]
        if not fip['router_id']:
            return
        router = self.l3plugin.get_router(context, fip['router_id'])
        if not self._is_user_defined_provider(context, router):
            return
        LOG.debug('Got request to create a floating ip associated to a router '
                  'of user defined flavor %s', fip)

    @registry.receives(resources.FLOATING_IP, [events.AFTER_UPDATE])
    def _process_floatingip_update(self, resource, event, trigger, payload):
        context = payload.context
        fip = payload.states[1]
        if not fip['router_id']:
            return
        router = self.l3plugin.get_router(context, fip['router_id'])
        if not self._is_user_defined_provider(context, router):
            return
        LOG.debug('Got request to update a floating ip associated to a router '
                  'of user defined flavor %s', fip)

    @registry.receives(resources.FLOATING_IP, [events.AFTER_DELETE])
    def _process_floatingip_delete(self, resource, event, trigger, payload):
        context = payload.context
        fip = payload.states[0]
        if not fip['router_id']:
            return
        router = self.l3plugin.get_router(context, fip['router_id'])
        if not self._is_user_defined_provider(context, router):
            return
        LOG.debug('Got request to delete a floating ip associated to a router '
                  'of user defined flavor %s', fip)

    @registry.receives(resources.FLOATING_IP, [events.AFTER_STATUS_UPDATE])
    def _process_floatingip_status_update(self, resource, event, trigger,
                                          payload):
        context = payload.context
        fip = payload.states[0]
        if not fip['router_id']:
            return
        router = self.l3plugin.get_router(context, fip['router_id'])
        if not self._is_user_defined_provider(context, router):
            return
        LOG.debug('Got request to update the status of a floating ip '
                  'associated to a router of user defined flavor %s', fip)


@registry.has_registry_receivers
class UserDefinedNoLsp(UserDefined):

    @registry.receives(resources.ROUTER_INTERFACE, [events.AFTER_CREATE])
    def _process_add_router_interface(self, resource, event, trigger, payload):
        router = payload.states[0]
        context = payload.context
        if not self._is_user_defined_provider(context, router):
            return
        port = payload.metadata['port']
        subnets = payload.metadata['subnets']
        router_interface_info = self.l3plugin._make_router_interface_info(
            router.id, port['tenant_id'], port['id'], port['network_id'],
            subnets[-1]['id'], [subnet['id'] for subnet in subnets])
        self.l3plugin._ovn_client.delete_port(context, port['id'],
                                              port_object=port)
        LOG.debug('Got request to add interface %s to a user defined flavor '
                  'router with id %s. The OVN LSP was deleted.',
                  router_interface_info, router.id)

    def _get_port_to_recreate(self, context, router_id, subnet_id):
        with db_api.CONTEXT_READER.using(context):
            objs = router.RouterPort.get_objects(
                context, router_id=router_id,
                port_type=const.DEVICE_OWNER_ROUTER_INTF)
            router_ports = [
                self.l3plugin._plugin._make_port_dict(rp.db_obj.port)
                for rp in objs]
        for rp in router_ports:
            for ip in rp['fixed_ips']:
                if ip['subnet_id'] == subnet_id:
                    return rp
        raise l3_exc.RouterInterfaceNotFoundForSubnet(router_ports=router_id,
                                                      subnet_id=subnet_id)

    @registry.receives(resources.ROUTER_INTERFACE, [events.BEFORE_DELETE])
    def _process_before_remove_router_interface(self, resource, event, trigger,
                                                payload):
        context = payload.context
        router_id = payload.resource_id
        router_obj = router.Router.get_object(context, id=router_id)
        if not self._is_user_defined_provider(context, router_obj):
            return
        subnet_id = payload.metadata['subnet_id']
        port = self._get_port_to_recreate(context, router_id, subnet_id)

        # If the LSP exists, the interface is being removed by port and the
        # port has fixed ips in more than one subnet, then the port has been
        # recreated in a previous notification of this event. Do nothing
        nbdb_idl = self.l3plugin._ovn_client._nb_idl
        if nbdb_idl.lookup('Logical_Switch_Port', port['id'], default=None):
            return

        # The ovn client creates the revision row when creating the LSP
        self.l3plugin._ovn_client.create_port(context, port)
        LOG.debug('Recreated OVN LSP for port with id %s before removing '
                  'interface for user defined flavor router with id %s',
                  port['id'], router_id)
