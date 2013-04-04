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
# @author: Akihiro MOTOKI

from quantum.plugins.nec.common import config
from quantum.plugins.nec.common import exceptions as nexc
from quantum.plugins.nec.db import api as ndb
from quantum.plugins.nec import drivers


class OFCManager(object):
    """This class manages an OpenFlow Controller and map resources.

    This class manage an OpenFlow Controller (OFC) with a driver specified in
    a configuration of this plugin.  This keeps mappings between IDs on Quantum
    and OFC for various entities such as Tenant, Network and Filter.  A Port on
    OFC is identified by a switch ID 'datapath_id' and a port number 'port_no'
    of the switch.  An ID named as 'ofc_*' is used to identify resource on OFC.
    """

    def __init__(self):
        self.driver = drivers.get_driver(config.OFC.driver)(config.OFC)

    def _get_ofc_id(self, context, resource, quantum_id):
        return ndb.get_ofc_id_lookup_both(context.session,
                                          resource, quantum_id)

    def _exists_ofc_item(self, context, resource, quantum_id):
        return ndb.exists_ofc_item_lookup_both(context.session,
                                               resource, quantum_id)

    def _add_ofc_item(self, context, resource, quantum_id, ofc_id):
        # Ensure a new item is added to the new mapping table
        ndb.add_ofc_item(context.session, resource, quantum_id, ofc_id)

    def _del_ofc_item(self, context, resource, quantum_id):
        ndb.del_ofc_item_lookup_both(context.session, resource, quantum_id)

    def create_ofc_tenant(self, context, tenant_id):
        desc = "ID=%s at OpenStack." % tenant_id
        ofc_tenant_id = self.driver.create_tenant(desc, tenant_id)
        self._add_ofc_item(context, "ofc_tenant", tenant_id, ofc_tenant_id)

    def exists_ofc_tenant(self, context, tenant_id):
        return self._exists_ofc_item(context, "ofc_tenant", tenant_id)

    def delete_ofc_tenant(self, context, tenant_id):
        ofc_tenant_id = self._get_ofc_id(context, "ofc_tenant", tenant_id)
        ofc_tenant_id = self.driver.convert_ofc_tenant_id(
            context, ofc_tenant_id)

        self.driver.delete_tenant(ofc_tenant_id)
        self._del_ofc_item(context, "ofc_tenant", tenant_id)

    def create_ofc_network(self, context, tenant_id, network_id,
                           network_name=None):
        ofc_tenant_id = self._get_ofc_id(context, "ofc_tenant", tenant_id)
        ofc_tenant_id = self.driver.convert_ofc_tenant_id(
            context, ofc_tenant_id)

        desc = "ID=%s Name=%s at Quantum." % (network_id, network_name)
        ofc_net_id = self.driver.create_network(ofc_tenant_id, desc,
                                                network_id)
        self._add_ofc_item(context, "ofc_network", network_id, ofc_net_id)

    def exists_ofc_network(self, context, network_id):
        return self._exists_ofc_item(context, "ofc_network", network_id)

    def delete_ofc_network(self, context, network_id, network):
        ofc_net_id = self._get_ofc_id(context, "ofc_network", network_id)
        ofc_net_id = self.driver.convert_ofc_network_id(
            context, ofc_net_id, network['tenant_id'])
        self.driver.delete_network(ofc_net_id)
        self._del_ofc_item(context, "ofc_network", network_id)

    def create_ofc_port(self, context, port_id, port):
        ofc_net_id = self._get_ofc_id(context, "ofc_network",
                                      port['network_id'])
        ofc_net_id = self.driver.convert_ofc_network_id(
            context, ofc_net_id, port['tenant_id'])
        portinfo = ndb.get_portinfo(context.session, port_id)
        if not portinfo:
            raise nexc.PortInfoNotFound(id=port_id)

        ofc_port_id = self.driver.create_port(ofc_net_id, portinfo, port_id)
        self._add_ofc_item(context, "ofc_port", port_id, ofc_port_id)

    def exists_ofc_port(self, context, port_id):
        return self._exists_ofc_item(context, "ofc_port", port_id)

    def delete_ofc_port(self, context, port_id, port):
        ofc_port_id = self._get_ofc_id(context, "ofc_port", port_id)
        ofc_port_id = self.driver.convert_ofc_port_id(
            context, ofc_port_id, port['tenant_id'], port['network_id'])
        self.driver.delete_port(ofc_port_id)
        self._del_ofc_item(context, "ofc_port", port_id)

    def create_ofc_packet_filter(self, context, filter_id, filter_dict):
        ofc_net_id = self._get_ofc_id(context, "ofc_network",
                                      filter_dict['network_id'])
        ofc_net_id = self.driver.convert_ofc_network_id(
            context, ofc_net_id, filter_dict['tenant_id'])
        in_port_id = filter_dict.get('in_port')
        portinfo = None
        if in_port_id:
            portinfo = ndb.get_portinfo(context.session, in_port_id)
            if not portinfo:
                raise nexc.PortInfoNotFound(id=in_port_id)

        ofc_pf_id = self.driver.create_filter(ofc_net_id,
                                              filter_dict, portinfo, filter_id)
        self._add_ofc_item(context, "ofc_packet_filter", filter_id, ofc_pf_id)

    def exists_ofc_packet_filter(self, context, filter_id):
        return self._exists_ofc_item(context, "ofc_packet_filter", filter_id)

    def delete_ofc_packet_filter(self, context, filter_id):
        ofc_pf_id = self._get_ofc_id(context, "ofc_packet_filter", filter_id)
        ofc_pf_id = self.driver.convert_ofc_filter_id(context, ofc_pf_id)

        self.driver.delete_filter(ofc_pf_id)
        self._del_ofc_item(context, "ofc_packet_filter", filter_id)
