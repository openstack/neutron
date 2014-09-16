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

import netaddr

from neutron.common import utils
from neutron.openstack.common import log as logging
from neutron.plugins.nec.common import config
from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec.db import api as ndb
from neutron.plugins.nec import drivers


LOG = logging.getLogger(__name__)


class OFCManager(object):
    """This class manages an OpenFlow Controller and map resources.

    This class manage an OpenFlow Controller (OFC) with a driver specified in
    a configuration of this plugin.  This keeps mappings between IDs on Neutron
    and OFC for various entities such as Tenant, Network and Filter.  A Port on
    OFC is identified by a switch ID 'datapath_id' and a port number 'port_no'
    of the switch.  An ID named as 'ofc_*' is used to identify resource on OFC.
    """

    def __init__(self, plugin):
        self.driver = drivers.get_driver(config.OFC.driver)(config.OFC)
        self.plugin = plugin

    def _get_ofc_id(self, context, resource, neutron_id):
        return ndb.get_ofc_id(context.session, resource, neutron_id)

    def _exists_ofc_item(self, context, resource, neutron_id):
        return ndb.exists_ofc_item(context.session, resource, neutron_id)

    def _add_ofc_item(self, context, resource, neutron_id, ofc_id):
        # Ensure a new item is added to the new mapping table
        ndb.add_ofc_item(context.session, resource, neutron_id, ofc_id)

    def _del_ofc_item(self, context, resource, neutron_id):
        ndb.del_ofc_item(context.session, resource, neutron_id)

    def ensure_ofc_tenant(self, context, tenant_id):
        if not self.exists_ofc_tenant(context, tenant_id):
            self.create_ofc_tenant(context, tenant_id)

    def create_ofc_tenant(self, context, tenant_id):
        desc = "ID=%s at OpenStack." % tenant_id
        ofc_tenant_id = self.driver.create_tenant(desc, tenant_id)
        self._add_ofc_item(context, "ofc_tenant", tenant_id, ofc_tenant_id)

    def exists_ofc_tenant(self, context, tenant_id):
        return self._exists_ofc_item(context, "ofc_tenant", tenant_id)

    def delete_ofc_tenant(self, context, tenant_id):
        ofc_tenant_id = self._get_ofc_id(context, "ofc_tenant", tenant_id)
        self.driver.delete_tenant(ofc_tenant_id)
        self._del_ofc_item(context, "ofc_tenant", tenant_id)

    def create_ofc_network(self, context, tenant_id, network_id,
                           network_name=None):
        ofc_tenant_id = self._get_ofc_id(context, "ofc_tenant", tenant_id)
        desc = "ID=%s Name=%s at Neutron." % (network_id, network_name)
        ofc_net_id = self.driver.create_network(ofc_tenant_id, desc,
                                                network_id)
        self._add_ofc_item(context, "ofc_network", network_id, ofc_net_id)

    def exists_ofc_network(self, context, network_id):
        return self._exists_ofc_item(context, "ofc_network", network_id)

    def delete_ofc_network(self, context, network_id, network):
        ofc_net_id = self._get_ofc_id(context, "ofc_network", network_id)
        self.driver.delete_network(ofc_net_id)
        self._del_ofc_item(context, "ofc_network", network_id)

    def create_ofc_port(self, context, port_id, port):
        ofc_net_id = self._get_ofc_id(context, "ofc_network",
                                      port['network_id'])
        portinfo = ndb.get_portinfo(context.session, port_id)
        if not portinfo:
            raise nexc.PortInfoNotFound(id=port_id)

        # Associate packet filters
        filters = self.plugin.get_packet_filters_for_port(context, port)
        if filters is not None:
            params = {'filters': filters}
        else:
            params = {}

        ofc_port_id = self.driver.create_port(ofc_net_id, portinfo, port_id,
                                              **params)
        self._add_ofc_item(context, "ofc_port", port_id, ofc_port_id)

    def exists_ofc_port(self, context, port_id):
        return self._exists_ofc_item(context, "ofc_port", port_id)

    def delete_ofc_port(self, context, port_id, port):
        ofc_port_id = self._get_ofc_id(context, "ofc_port", port_id)
        self.driver.delete_port(ofc_port_id)
        self._del_ofc_item(context, "ofc_port", port_id)

    def create_ofc_packet_filter(self, context, filter_id, filter_dict):
        ofc_net_id = self._get_ofc_id(context, "ofc_network",
                                      filter_dict['network_id'])
        in_port_id = filter_dict.get('in_port')
        portinfo = None
        if in_port_id:
            portinfo = ndb.get_portinfo(context.session, in_port_id)
            if not portinfo:
                raise nexc.PortInfoNotFound(id=in_port_id)

        # Collect ports to be associated with the filter
        apply_ports = ndb.get_active_ports_on_ofc(
            context, filter_dict['network_id'], in_port_id)
        ofc_pf_id = self.driver.create_filter(ofc_net_id,
                                              filter_dict, portinfo, filter_id,
                                              apply_ports)
        self._add_ofc_item(context, "ofc_packet_filter", filter_id, ofc_pf_id)

    def update_ofc_packet_filter(self, context, filter_id, filter_dict):
        ofc_pf_id = self._get_ofc_id(context, "ofc_packet_filter", filter_id)
        ofc_pf_id = self.driver.convert_ofc_filter_id(context, ofc_pf_id)
        self.driver.update_filter(ofc_pf_id, filter_dict)

    def exists_ofc_packet_filter(self, context, filter_id):
        return self._exists_ofc_item(context, "ofc_packet_filter", filter_id)

    def delete_ofc_packet_filter(self, context, filter_id):
        ofc_pf_id = self._get_ofc_id(context, "ofc_packet_filter", filter_id)
        self.driver.delete_filter(ofc_pf_id)
        self._del_ofc_item(context, "ofc_packet_filter", filter_id)

    def create_ofc_router(self, context, tenant_id, router_id, name=None):
        ofc_tenant_id = self._get_ofc_id(context, "ofc_tenant", tenant_id)
        desc = "ID=%s Name=%s at Neutron." % (router_id, name)
        ofc_router_id = self.driver.create_router(ofc_tenant_id, router_id,
                                                  desc)
        self._add_ofc_item(context, "ofc_router", router_id, ofc_router_id)

    def exists_ofc_router(self, context, router_id):
        return self._exists_ofc_item(context, "ofc_router", router_id)

    def delete_ofc_router(self, context, router_id, router):
        ofc_router_id = self._get_ofc_id(context, "ofc_router", router_id)
        self.driver.delete_router(ofc_router_id)
        self._del_ofc_item(context, "ofc_router", router_id)

    def add_ofc_router_interface(self, context, router_id, port_id, port):
        # port must have the following fields:
        #   network_id, cidr, ip_address, mac_address
        ofc_router_id = self._get_ofc_id(context, "ofc_router", router_id)
        ofc_net_id = self._get_ofc_id(context, "ofc_network",
                                      port['network_id'])
        ip_address = '%s/%s' % (port['ip_address'],
                                netaddr.IPNetwork(port['cidr']).prefixlen)
        mac_address = port['mac_address']
        ofc_inf_id = self.driver.add_router_interface(
            ofc_router_id, ofc_net_id, ip_address, mac_address)
        # Use port mapping table to maintain an interface of OFC router
        self._add_ofc_item(context, "ofc_port", port_id, ofc_inf_id)

    def delete_ofc_router_interface(self, context, router_id, port_id):
        # Use port mapping table to maintain an interface of OFC router
        ofc_inf_id = self._get_ofc_id(context, "ofc_port", port_id)
        self.driver.delete_router_interface(ofc_inf_id)
        self._del_ofc_item(context, "ofc_port", port_id)

    def update_ofc_router_route(self, context, router_id, new_routes):
        ofc_router_id = self._get_ofc_id(context, "ofc_router", router_id)
        ofc_routes = self.driver.list_router_routes(ofc_router_id)
        route_dict = {}
        cur_routes = []
        for r in ofc_routes:
            key = ','.join((r['destination'], r['nexthop']))
            route_dict[key] = r['id']
            del r['id']
            cur_routes.append(r)
        added, removed = utils.diff_list_of_dict(cur_routes, new_routes)
        for r in removed:
            key = ','.join((r['destination'], r['nexthop']))
            route_id = route_dict[key]
            self.driver.delete_router_route(route_id)
        for r in added:
            self.driver.add_router_route(ofc_router_id, r['destination'],
                                         r['nexthop'])
