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
#
# @author: Arvind Somya (asomya@cisco.com), Cisco Systems Inc.

from neutron.db import api as qdbapi
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.db import model_base
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.plugins.ml2.drivers.cisco.apic import apic_manager

LOG = logging.getLogger(__name__)


class ApicL3ServicePlugin(db_base_plugin_v2.NeutronDbPluginV2,
                          db_base_plugin_v2.CommonDbMixin,
                          extraroute_db.ExtraRoute_db_mixin,
                          l3_gwmode_db.L3_NAT_db_mixin):
    """Implementation of the APIC L3 Router Service Plugin.

    This class implements a L3 service plugin that provides
    internal gateway functionality for the Cisco APIC (Application
    Policy Infrastructure Controller).
    """
    supported_extension_aliases = ["router", "ext-gw-mode", "extraroute"]

    def __init__(self):
        super(ApicL3ServicePlugin, self).__init__()
        qdbapi.register_models(base=model_base.BASEV2)
        self.manager = apic_manager.APICManager()

    @staticmethod
    def get_plugin_type():
        return constants.L3_ROUTER_NAT

    @staticmethod
    def get_plugin_description():
        """Returns string description of the plugin."""
        return _("L3 Router Service Plugin for basic L3 using the APIC")

    def _add_epg_to_contract(self, tenant_id, epg, contract):
        """Add an End Point Group(EPG) to a contract as provider/consumer."""
        if self.manager.db.get_provider_contract():
            # Set this network's EPG as a consumer
            self.manager.set_contract_for_epg(tenant_id, epg.epg_id,
                                              contract.contract_id)
        else:
            # Set this network's EPG as a provider
            self.manager.set_contract_for_epg(tenant_id, epg.epg_id,
                                              contract.contract_id,
                                              provider=True)

    def add_router_interface(self, context, router_id, interface_info):
        """Attach a subnet to a router."""
        tenant_id = context.tenant_id
        subnet_id = interface_info['subnet_id']
        LOG.debug("Attaching subnet %(subnet_id)s to "
                  "router %(router_id)s" % {'subnet_id': subnet_id,
                                            'router_id': router_id})

        # Get network for this subnet
        subnet = self.get_subnet(context, subnet_id)
        network_id = subnet['network_id']
        net_name = self.get_network(context, network_id)['name']

        # Setup tenant filters and contracts
        contract = self.manager.create_tenant_contract(tenant_id)

        # Check for a provider EPG
        epg = self.manager.ensure_epg_created_for_network(tenant_id,
                                                          network_id,
                                                          net_name)
        self._add_epg_to_contract(tenant_id, epg, contract)

        # Create DB port
        try:
            return super(ApicL3ServicePlugin, self).add_router_interface(
                context, router_id, interface_info)
        except Exception:
            LOG.error(_("Error attaching subnet %(subnet_id)s to "
                        "router %(router_id)s") % {'subnet_id': subnet_id,
                                                   'router_id': router_id})
            with excutils.save_and_reraise_exception():
                self.manager.delete_contract_for_epg(tenant_id, epg.epg_id,
                                                     contract.contract_id,
                                                     provider=epg.provider)

    def remove_router_interface(self, context, router_id, interface_info):
        """Detach a subnet from a router."""
        tenant_id = context.tenant_id
        subnet_id = interface_info['subnet_id']
        LOG.debug("Detaching subnet %(subnet_id)s from "
                  "router %(router_id)s" % {'subnet_id': subnet_id,
                                            'router_id': router_id})

        # Get network for this subnet
        subnet = self.get_subnet(context, subnet_id)
        network_id = subnet['network_id']
        network = self.get_network(context, network_id)

        contract = self.manager.create_tenant_contract(tenant_id)

        epg = self.manager.ensure_epg_created_for_network(tenant_id,
                                                          network_id,
                                                          network['name'])
        # Delete contract for this epg
        self.manager.delete_contract_for_epg(tenant_id, epg.epg_id,
                                             contract.contract_id,
                                             provider=epg.provider)

        try:
            return super(ApicL3ServicePlugin, self).remove_router_interface(
                context, router_id, interface_info)
        except Exception:
            LOG.error(_("Error detaching subnet %(subnet_id)s from "
                        "router %(router_id)s") % {'subnet_id': subnet_id,
                                                   'router_id': router_id})
            with excutils.save_and_reraise_exception():
                self._add_epg_to_contract(tenant_id, epg, contract)
