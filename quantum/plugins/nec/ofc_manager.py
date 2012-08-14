# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2012 NEC Corporation.  All rights reserved.
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
# @author: Ryota MIBU

from quantum.plugins.nec import drivers
from quantum.plugins.nec.common import config
from quantum.plugins.nec.common import exceptions as nexc
from quantum.plugins.nec.db import api as ndb
from quantum.plugins.nec.db import models as nmodels


class OFCManager(object):
    """This class manages an OpenFlow Controller and map resources.

    This class manage an OpenFlow Controller (OFC) with a driver specified in
    a configuration of this plugin.  This keeps mappings between IDs on Quantum
    and OFC for various entities such as Tenant, Network and Filter.  A Port on
    OFC is identified by a switch ID 'datapath_id' and a port number 'port_no'
    of the switch.  An ID named as 'ofc_*' is used to identify resource on OFC.
    """
    resource_map = {'ofc_tenant': nmodels.OFCTenant,
                    'ofc_network': nmodels.OFCNetwork,
                    'ofc_port': nmodels.OFCPort,
                    'ofc_packet_filter': nmodels.OFCFilter}

    def __init__(self):
        self.driver = drivers.get_driver(config.OFC.driver)(config.OFC)

    def _get_ofc_id(self, resource, quantum_id):
        model = self.resource_map[resource]
        ofc_item = ndb.find_ofc_item(model, quantum_id)
        if not ofc_item:
            reason = "NotFound %s for quantum_id=%s." % (resource, quantum_id)
            raise nexc.OFCConsistencyBroken(reason=reason)
        return ofc_item.id

    def _exists_ofc_item(self, resource, quantum_id):
        model = self.resource_map[resource]
        if ndb.find_ofc_item(model, quantum_id):
            return True
        else:
            return False

    # Tenant

    def create_ofc_tenant(self, tenant_id):
        desc = "ID=%s at OpenStack." % tenant_id
        ofc_tenant_id = self.driver.create_tenant(desc, tenant_id)
        ndb.add_ofc_item(nmodels.OFCTenant, ofc_tenant_id, tenant_id)

    def exists_ofc_tenant(self, tenant_id):
        return self._exists_ofc_item("ofc_tenant", tenant_id)

    def delete_ofc_tenant(self, tenant_id):
        ofc_tenant_id = self._get_ofc_id("ofc_tenant", tenant_id)

        self.driver.delete_tenant(ofc_tenant_id)
        ndb.del_ofc_item(nmodels.OFCTenant, ofc_tenant_id)

    # Network

    def create_ofc_network(self, tenant_id, network_id, network_name=None):
        ofc_tenant_id = self._get_ofc_id("ofc_tenant", tenant_id)

        desc = "ID=%s Name=%s at Quantum." % (network_id, network_name)
        ofc_net_id = self.driver.create_network(ofc_tenant_id, desc,
                                                network_id)
        ndb.add_ofc_item(nmodels.OFCNetwork, ofc_net_id, network_id)

    def update_ofc_network(self, tenant_id, network_id, network_name):
        ofc_tenant_id = self._get_ofc_id("ofc_tenant", tenant_id)
        ofc_net_id = self._get_ofc_id("ofc_network", network_id)

        desc = "ID=%s Name=%s at Quantum." % (network_id, network_name)
        self.driver.update_network(ofc_tenant_id, ofc_net_id, desc)

    def exists_ofc_network(self, network_id):
        return self._exists_ofc_item("ofc_network", network_id)

    def delete_ofc_network(self, tenant_id, network_id):
        ofc_tenant_id = self._get_ofc_id("ofc_tenant", tenant_id)
        ofc_net_id = self._get_ofc_id("ofc_network", network_id)

        self.driver.delete_network(ofc_tenant_id, ofc_net_id)
        ndb.del_ofc_item(nmodels.OFCNetwork, ofc_net_id)

    # Port

    def create_ofc_port(self, tenant_id, network_id, port_id):
        ofc_tenant_id = self._get_ofc_id("ofc_tenant", tenant_id)
        ofc_net_id = self._get_ofc_id("ofc_network", network_id)
        portinfo = ndb.get_portinfo(port_id)
        if not portinfo:
            raise nexc.PortInfoNotFound(id=port_id)

        ofc_port_id = self.driver.create_port(ofc_tenant_id, ofc_net_id,
                                              portinfo, port_id)
        ndb.add_ofc_item(nmodels.OFCPort, ofc_port_id, port_id)

    def exists_ofc_port(self, port_id):
        return self._exists_ofc_item("ofc_port", port_id)

    def delete_ofc_port(self, tenant_id, network_id, port_id):
        ofc_tenant_id = self._get_ofc_id("ofc_tenant", tenant_id)
        ofc_net_id = self._get_ofc_id("ofc_network", network_id)
        ofc_port_id = self._get_ofc_id("ofc_port", port_id)

        self.driver.delete_port(ofc_tenant_id, ofc_net_id, ofc_port_id)
        ndb.del_ofc_item(nmodels.OFCPort, ofc_port_id)

    # PacketFilter

    def create_ofc_packet_filter(self, tenant_id, network_id, filter_id,
                                 filter_dict):
        ofc_tenant_id = self._get_ofc_id("ofc_tenant", tenant_id)
        ofc_net_id = self._get_ofc_id("ofc_network", network_id)
        in_port_id = filter_dict.get('in_port')
        portinfo = None
        if in_port_id:
            portinfo = ndb.get_portinfo(in_port_id)
            if not portinfo:
                raise nexc.PortInfoNotFound(id=in_port_id)

        ofc_pf_id = self.driver.create_filter(ofc_tenant_id, ofc_net_id,
                                              filter_dict, portinfo, filter_id)
        ndb.add_ofc_item(nmodels.OFCFilter, ofc_pf_id, filter_id)

    def exists_ofc_packet_filter(self, filter_id):
        return self._exists_ofc_item("ofc_packet_filter", filter_id)

    def delete_ofc_packet_filter(self, tenant_id, network_id, filter_id):
        ofc_tenant_id = self._get_ofc_id("ofc_tenant", tenant_id)
        ofc_net_id = self._get_ofc_id("ofc_network", network_id)
        ofc_pf_id = self._get_ofc_id("ofc_packet_filter", filter_id)

        res = self.driver.delete_filter(ofc_tenant_id, ofc_net_id, ofc_pf_id)
        ndb.del_ofc_item(nmodels.OFCFilter, ofc_pf_id)
