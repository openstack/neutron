# Copyright 2026 Red Hat, LLC
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

from neutron_lib.api.definitions import evpn as evpn_apidef
from neutron_lib.api.definitions import l3 as l3_apidef
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib.db import resource_extend
from neutron_lib.plugins import constants as plugin_constants
from neutron_lib.services import base as service_base
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


# TODO(jlibosva):  Remove once the DB layer is implemented
def _fake_db_call(action):
    pass


@resource_extend.has_resource_extenders
@registry.has_registry_receivers
class EVPNPlugin(service_base.ServicePluginBase):
    """EVPN service plugin.

    This plugin extends the router API with an ``evpn_vni`` attribute
    and the router-interface API with EVPN advertisement controls.
    """

    supported_extension_aliases = [evpn_apidef.ALIAS]

    __native_pagination_support = True
    __native_sorting_support = True

    def __init__(self):
        super().__init__()
        LOG.info("Starting EVPN service plugin")

    def get_plugin_description(self):
        return "EVPN service plugin"

    @classmethod
    def get_plugin_type(cls):
        return plugin_constants.EVPN

    @staticmethod
    @resource_extend.extends([l3_apidef.ROUTERS])
    def _extend_router_dict(router_res, router_db):
        LOG.debug("EVPN extending router dict router_res: %s "
                  "router_db: %s", router_res, router_db)
        router_res[evpn_apidef.EVPN_VNI] = None
        if router_db.get('evpn_vni_allocation'):
            router_res[evpn_apidef.EVPN_VNI] = (
                router_db['evpn_vni_allocation'].evpn_vni)
        return router_res

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_CREATE])
    def _process_router_create(self, resource, event, trigger, payload):
        LOG.debug("EVPN processing router create - resource: %s "
                  "event: %s trigger: %s payload: %s",
                  resource, event, trigger, payload)
        # TODO(jlibosva):  Implement the actual DB call
        _fake_db_call('create evpn')

    @registry.receives(resources.ROUTER, [events.PRECOMMIT_DELETE])
    def _process_router_delete(self, resource, event, trigger, payload):
        LOG.debug("EVPN processing router delete - resource: %s "
                  "event: %s trigger: %s payload: %s",
                  resource, event, trigger, payload)
        # TODO(jlibosva):  Implement the actual DB call
        _fake_db_call('delete evpn')

    @registry.receives(resources.ROUTER_INTERFACE, [events.BEFORE_CREATE])
    def _process_router_interface_create(self, resource, event, trigger,
                                         payload):
        """Handle router interface addition for EVPN advertisement.

        If advertise_host is requested in the interface_info, create
        evpn_networks and evpn_advertised_ports entries within the same
        transaction as the router interface creation.
        """
        router_id = payload.resource_id
        interface_info = payload.metadata.get('interface_info', {})

        if not interface_info.get(evpn_apidef.ADVERTISE_HOST):
            LOG.debug("EVPN interface create no advertise_host requested: %s",
                     interface_info.get(evpn_apidef.ADVERTISE_HOST))
            return

        port = payload.metadata['port']
        network_id = port['network_id']
        port_id = port['id']

        # TODO(jlibosva):  Implement the actual DB call
        _fake_db_call('advertise port')
        LOG.info("EVPN advertise_host enabled for port %s on router %s and "
                 "network %s", port_id, router_id, network_id)

    @registry.receives(resources.ROUTER_INTERFACE, [events.BEFORE_DELETE])
    def _process_router_interface_delete(self, resource, event, trigger,
                                         payload):
        """Remove evpn_networks entry when subnet is detached from router.

        This ensures the RESTRICT FK on evpn_networks.network_id does not
        block future network deletion.
        """
        subnet_id = payload.metadata['subnet_id']
        # TODO(jlibosva):  Implement the actual DB call
        _fake_db_call('remove port')
        LOG.info("Removing EVPN network entry for subnet %s", subnet_id)
