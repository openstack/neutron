# Copyright (c) 2014 Cisco Systems Inc.
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

from apicapi import apic_mapper
from oslo_utils import excutils

from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_dvr_db
from neutron.plugins.common import constants

from neutron.plugins.ml2.drivers.cisco.apic import mechanism_apic


class ApicL3ServicePlugin(db_base_plugin_v2.NeutronDbPluginV2,
                          l3_dvr_db.L3_NAT_with_dvr_db_mixin,
                          extraroute_db.ExtraRoute_db_mixin):
    supported_extension_aliases = ["router", "ext-gw-mode", "extraroute"]

    def __init__(self):
        super(ApicL3ServicePlugin, self).__init__()
        self.manager = mechanism_apic.APICMechanismDriver.get_apic_manager()
        self.name_mapper = self.manager.apic_mapper
        self.synchronizer = None
        self.manager.ensure_infra_created_on_apic()
        self.manager.ensure_bgp_pod_policy_created_on_apic()

    def _map_names(self, context,
                   tenant_id, router_id, net_id, subnet_id):
        context._plugin = self
        with apic_mapper.mapper_context(context) as ctx:
            atenant_id = tenant_id and self.name_mapper.tenant(ctx, tenant_id)
            arouter_id = router_id and self.name_mapper.router(ctx, router_id)
            anet_id = net_id and self.name_mapper.network(ctx, net_id)
            asubnet_id = subnet_id and self.name_mapper.subnet(ctx, subnet_id)
        return atenant_id, arouter_id, anet_id, asubnet_id

    @staticmethod
    def get_plugin_type():
        return constants.L3_ROUTER_NAT

    @staticmethod
    def get_plugin_description():
        """Returns string description of the plugin."""
        return _("L3 Router Service Plugin for basic L3 using the APIC")

    def sync_init(f):
        def inner(inst, *args, **kwargs):
            if not inst.synchronizer:
                inst.synchronizer = (
                    mechanism_apic.APICMechanismDriver.
                    get_router_synchronizer(inst))
                inst.synchronizer.sync_router()
            # pylint: disable=not-callable
            return f(inst, *args, **kwargs)
        return inner

    def add_router_interface_postcommit(self, context, router_id,
                                        interface_info):
        # Update router's state first
        router = self.get_router(context, router_id)
        self.update_router_postcommit(context, router)

        # Add router interface
        if 'subnet_id' in interface_info:
            subnet = self.get_subnet(context, interface_info['subnet_id'])
            network_id = subnet['network_id']
            tenant_id = subnet['tenant_id']
        else:
            port = self.get_port(context, interface_info['port_id'])
            network_id = port['network_id']
            tenant_id = port['tenant_id']

        # Map openstack IDs to APIC IDs
        atenant_id, arouter_id, anetwork_id, _ = self._map_names(
            context, tenant_id, router_id, network_id, None)

        # Program APIC
        self.manager.add_router_interface(atenant_id, arouter_id,
                                          anetwork_id)

    def remove_router_interface_precommit(self, context, router_id,
                                          interface_info):
        if 'subnet_id' in interface_info:
            subnet = self.get_subnet(context, interface_info['subnet_id'])
            network_id = subnet['network_id']
            tenant_id = subnet['tenant_id']
        else:
            port = self.get_port(context, interface_info['port_id'])
            network_id = port['network_id']
            tenant_id = port['tenant_id']

        # Map openstack IDs to APIC IDs
        atenant_id, arouter_id, anetwork_id, _ = self._map_names(
            context, tenant_id, router_id, network_id, None)

        # Program APIC
        self.manager.remove_router_interface(atenant_id, arouter_id,
                                             anetwork_id)

    def delete_router_precommit(self, context, router_id):
        context._plugin = self
        with apic_mapper.mapper_context(context) as ctx:
            arouter_id = router_id and self.name_mapper.router(ctx, router_id)
        self.manager.delete_router(arouter_id)

    def update_router_postcommit(self, context, router):
        context._plugin = self
        with apic_mapper.mapper_context(context) as ctx:
            arouter_id = router['id'] and self.name_mapper.router(ctx,
                                                                  router['id'])
        with self.manager.apic.transaction() as trs:
            self.manager.create_router(arouter_id, transaction=trs)
            if router['admin_state_up']:
                self.manager.enable_router(arouter_id, transaction=trs)
            else:
                self.manager.disable_router(arouter_id, transaction=trs)

    # Router API

    @sync_init
    def create_router(self, *args, **kwargs):
        return super(ApicL3ServicePlugin, self).create_router(*args, **kwargs)

    @sync_init
    def update_router(self, context, id, router):
        result = super(ApicL3ServicePlugin, self).update_router(context,
                                                                id, router)
        self.update_router_postcommit(context, result)
        return result

    @sync_init
    def get_router(self, *args, **kwargs):
        return super(ApicL3ServicePlugin, self).get_router(*args, **kwargs)

    @sync_init
    def get_routers(self, *args, **kwargs):
        return super(ApicL3ServicePlugin, self).get_routers(*args, **kwargs)

    @sync_init
    def get_routers_count(self, *args, **kwargs):
        return super(ApicL3ServicePlugin, self).get_routers_count(*args,
                                                                  **kwargs)

    def delete_router(self, context, router_id):
        self.delete_router_precommit(context, router_id)
        result = super(ApicL3ServicePlugin, self).delete_router(context,
                                                                router_id)
        return result

    # Router Interface API

    @sync_init
    def add_router_interface(self, context, router_id, interface_info):
        # Create interface in parent
        result = super(ApicL3ServicePlugin, self).add_router_interface(
            context, router_id, interface_info)
        try:
            self.add_router_interface_postcommit(context, router_id,
                                                 interface_info)
        except Exception:
            with excutils.save_and_reraise_exception():
                # Rollback db operation
                super(ApicL3ServicePlugin, self).remove_router_interface(
                    context, router_id, interface_info)
        return result

    def remove_router_interface(self, context, router_id, interface_info):
        self.remove_router_interface_precommit(context, router_id,
                                               interface_info)
        return super(ApicL3ServicePlugin, self).remove_router_interface(
            context, router_id, interface_info)
