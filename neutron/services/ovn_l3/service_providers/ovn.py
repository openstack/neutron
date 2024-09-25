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


import copy

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib.db import api as db_api
from oslo_log import log as logging
from oslo_utils import excutils

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.db import ovn_l3_hamode_db as ovn_l3_ha
from neutron.db import ovn_revision_numbers_db as db_rev
from neutron.extensions import revisions
from neutron.objects import router as l3_obj
from neutron.services.l3_router.service_providers import base
from neutron.services.portforwarding import constants as pf_consts


LOG = logging.getLogger(__name__)


@registry.has_registry_receivers
class OvnDriver(base.L3ServiceProvider,
                ovn_l3_ha.OVN_L3_HA_db_mixin):
    ha_support = base.MANDATORY
    distributed_support = base.MANDATORY

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_CREATE])
    def _process_router_create_precommit(self, resource, event, trigger,
                                         payload):
        context = payload.context
        context.session.flush()
        router_id = payload.resource_id
        router_db = payload.metadata['router_db']
        router = payload.states[0]
        if not utils.is_ovn_provider_router(router):
            return

        # NOTE(ralonsoh): the "distributed" flag is a static configuration
        # parameter that needs to be defined only during the router creation.
        extra_attr = router_db['extra_attributes']
        extra_attr.distributed = ovn_conf.is_ovn_distributed_floating_ip()

        db_rev.create_initial_revision(
            context, router_id, ovn_const.TYPE_ROUTERS,
            std_attr_id=router_db.standard_attr_id)

    @registry.receives(resources.ROUTER, [events.AFTER_CREATE])
    def _process_router_create(self, resource, event, trigger, payload):
        router = payload.states[0]
        if not utils.is_ovn_provider_router(router):
            return
        context = payload.context
        try:
            self.l3plugin._ovn_client.create_router(context, router)
        except Exception:
            with excutils.save_and_reraise_exception():
                # Delete the logical router
                LOG.exception('Unable to create lrouter %s', router['id'])
                self.l3plugin.delete_router(context, router['id'])

    @registry.receives(resources.ROUTER, [events.AFTER_UPDATE])
    def _process_router_update(self, resource, event, trigger, payload):
        router_id = payload.resource_id
        original = payload.states[0]
        updated = payload.states[1]
        if not utils.is_ovn_provider_router(original):
            # flavor_id attribute is not allowed in router PUTs, so we only
            # need to check the original router
            return
        context = payload.context
        try:
            self.l3plugin._ovn_client.update_router(context, updated, original)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Unable to update lrouter %s', router_id)
                revert_router = {'router': original}
                self.l3plugin.update_router(context, router_id, revert_router)

    @registry.receives(resources.ROUTER, [events.AFTER_DELETE])
    def _process_router_delete(self, resource, event, trigger, payload):
        router_id = payload.resource_id
        router = payload.states[0]
        if not utils.is_ovn_provider_router(router):
            return
        context = payload.context
        try:
            self.l3plugin._ovn_client.delete_router(context, router_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Unable to delete lrouter %s', router['id'])
                self.l3plugin.create_router(context, {'router': router})

    @registry.receives(resources.ROUTER_INTERFACE, [events.AFTER_CREATE])
    def _process_add_router_interface(self, resource, event, trigger, payload):
        router = payload.states[0]
        if not utils.is_ovn_provider_router(router):
            return
        context = payload.context
        port = payload.metadata['port']
        subnets = payload.metadata['subnets']
        router_interface_info = self.l3plugin._make_router_interface_info(
            router.id, port['tenant_id'], port['id'], port['network_id'],
            subnets[-1]['id'], [subnet['id'] for subnet in subnets])
        try:
            self.l3plugin._ovn_client.create_router_port(context, router.id,
                                                         router_interface_info)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Unable to add router interface to lrouter %s. '
                              'Interface info: %s', router['id'],
                              router_interface_info)
                self.l3plugin.remove_router_interface(context, router.id,
                                                      router_interface_info)

    @registry.receives(resources.ROUTER_INTERFACE, [events.AFTER_DELETE])
    def _process_remove_router_interface(self, resource, event, trigger,
                                         payload):
        router = payload.states[0]
        if not utils.is_ovn_provider_router(router):
            return
        context = payload.context
        port = payload.metadata['port']
        subnet_ids = payload.metadata['subnet_ids']
        router_interface_info = self.l3plugin._make_router_interface_info(
            router.id, port['tenant_id'], port['id'], port['network_id'],
            subnet_ids[0], subnet_ids)
        try:
            self.l3plugin._ovn_client.delete_router_port(context, port['id'],
                                                         subnet_ids=subnet_ids)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception('Unable to remove router interface from lrouter '
                              '%s. Interface info: %s', router['id'],
                              router_interface_info)
                self.l3plugin.add_router_interface(
                    context, router.id, payload.metadata['interface_info'])

    def _create_floatingip_initial_revision(self, context, floatingip_db):
        if not floatingip_db.router_id:
            return
        # We get the router with elevated context because floating IPs may be
        # created to be associated with a router created by a different
        # project. Please see
        # https://review.opendev.org/c/openstack/neutron/+/2727B09
        router = self.l3plugin.get_router(context.elevated(),
                                          floatingip_db.router_id)
        if not utils.is_ovn_provider_router(router):
            return
        db_rev.create_initial_revision(
            context, floatingip_db.id, ovn_const.TYPE_FLOATINGIPS,
            may_exist=True, std_attr_id=floatingip_db.standard_attr_id)

    @registry.receives(resources.FLOATING_IP,
                       [events.PRECOMMIT_CREATE, events.PRECOMMIT_UPDATE])
    def _process_floatingip_create_update_precommit(self, resource, event,
                                                    trigger, payload):
        context = payload.context
        floatingip_db = payload.desired_state
        self._create_floatingip_initial_revision(context, floatingip_db)

    @registry.receives(pf_consts.PORT_FORWARDING, [events.AFTER_CREATE])
    def _process_portforwarding_create(self, resource, event, trigger,
                                       payload):
        context = payload.context
        pf_obj = payload.states[0]
        with db_api.CONTEXT_WRITER.using(context):
            fip_db = l3_obj.FloatingIP.get_object(
                context, id=pf_obj.floatingip_id).db_obj
            self._create_floatingip_initial_revision(context, fip_db)

    @registry.receives(resources.FLOATING_IP, [events.AFTER_CREATE])
    def _process_floatingip_create(self, resource, event, trigger, payload):
        revision_row = db_rev.get_revision_row(payload.context,
                                               payload.resource_id)
        if not revision_row:
            return
        # The floating ip dictionary that is sent by the L3 DB plugin in the
        # notification doesn't include the revision number yet. We add it here
        # to the dictionary that is passed to the ovn client
        floatingip = copy.deepcopy(payload.states[0])
        floatingip[revisions.REVISION] = revision_row.revision_number
        qos_policy_id = payload.request_body['floatingip'].get('qos_policy_id')
        if qos_policy_id and 'qos_policy_id' not in floatingip:
            floatingip['qos_policy_id'] = qos_policy_id
        self.l3plugin._ovn_client.create_floatingip(payload.context,
                                                    floatingip)

    @registry.receives(resources.FLOATING_IP, [events.AFTER_UPDATE])
    def _process_floatingip_update(self, resource, event, trigger, payload):
        if not db_rev.get_revision_row(payload.context, payload.resource_id):
            return
        fip = payload.states[1]
        old_fip = payload.states[0]
        fip_request = payload.request_body
        if fip_request:
            self.l3plugin._ovn_client.update_floatingip(payload.context, fip,
                                                        fip_request)
        else:
            router_id = old_fip.get('router_id')
            fixed_ip_address = old_fip.get('fixed_ip_address')
            if router_id and fixed_ip_address:
                update_fip = {
                    'id': old_fip['id'],
                    'logical_ip': fixed_ip_address,
                    'external_ip': old_fip['floating_ip_address'],
                    'floating_network_id': old_fip['floating_network_id']
                }
                try:
                    self.l3plugin._ovn_client.disassociate_floatingip(
                        update_fip, router_id)
                    self.l3plugin.update_floatingip_status(
                        payload.context, old_fip['id'],
                        constants.FLOATINGIP_STATUS_DOWN)
                except Exception as e:
                    LOG.error('Error in disassociating floatingip %(id)s: '
                              '%(error)s', {'id': old_fip['id'], 'error': e})
        if not fip['router_id']:
            db_rev.delete_revision(payload.context, payload.resource_id,
                                   ovn_const.TYPE_FLOATINGIPS)

    @registry.receives(resources.FLOATING_IP, [events.AFTER_DELETE])
    def _process_floatingip_delete(self, resource, event, trigger, payload):
        if not db_rev.get_revision_row(payload.context, payload.resource_id):
            return
        self.l3plugin._ovn_client.delete_floatingip(payload.context,
                                                    payload.resource_id)

    @registry.receives(resources.FLOATING_IP, [events.AFTER_STATUS_UPDATE])
    def _process_floatingip_status_update(self, resource, event, trigger,
                                          payload):
        if not db_rev.get_revision_row(payload.context, payload.resource_id):
            return
        self.l3plugin._ovn_client.update_floatingip_status(payload.context,
                                                           payload.states[0])
