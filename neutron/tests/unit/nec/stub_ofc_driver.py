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

from neutron.common import log as call_log
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.nec.common import exceptions as nexc
from neutron.plugins.nec import ofc_driver_base


LOG = logging.getLogger(__name__)

MAX_NUM_OPENFLOW_ROUTER = 2


class StubOFCDriver(ofc_driver_base.OFCDriverBase):
    """Stub OFC driver for testing.

    This driver can be used not only for unit tests but also for real testing
    as a logging driver. It stores the created resources on OFC and returns
    them in get methods().

    If autocheck is enabled, it checks whether the specified resource exists
    in OFC and raises an exception if it is different from expected status.
    """

    def __init__(self, conf):
        self.autocheck = False
        self.reset_all()

    def reset_all(self):
        self.ofc_tenant_dict = {}
        self.ofc_network_dict = {}
        self.ofc_port_dict = {}
        self.ofc_filter_dict = {}
        self.ofc_router_dict = {}
        self.ofc_router_inf_dict = {}
        self.ofc_router_route_dict = {}

    def enable_autocheck(self):
        self.autocheck = True

    def disable_autocheck(self):
        self.autocheck = False

    @call_log.log
    def create_tenant(self, description, tenant_id=None):
        ofc_id = "ofc-" + tenant_id[:-4]
        if self.autocheck:
            if ofc_id in self.ofc_tenant_dict:
                raise Exception(_('(create_tenant) OFC tenant %s '
                                  'already exists') % ofc_id)
        self.ofc_tenant_dict[ofc_id] = {'tenant_id': tenant_id,
                                        'description': description}
        return ofc_id

    @call_log.log
    def delete_tenant(self, ofc_tenant_id):
        if ofc_tenant_id in self.ofc_tenant_dict:
            del self.ofc_tenant_dict[ofc_tenant_id]
        else:
            if self.autocheck:
                raise Exception(_('(delete_tenant) OFC tenant %s not found')
                                % ofc_tenant_id)
        LOG.debug(_('delete_tenant: SUCCEED'))

    @call_log.log
    def create_network(self, ofc_tenant_id, description, network_id=None):
        ofc_id = "ofc-" + network_id[:-4]
        if self.autocheck:
            if ofc_tenant_id not in self.ofc_tenant_dict:
                raise Exception(_('(create_network) OFC tenant %s not found')
                                % ofc_tenant_id)
            if ofc_id in self.ofc_network_dict:
                raise Exception(_('(create_network) OFC network %s '
                                  'already exists') % ofc_id)
        self.ofc_network_dict[ofc_id] = {'tenant_id': ofc_tenant_id,
                                         'network_id': network_id,
                                         'description': description}
        return ofc_id

    @call_log.log
    def update_network(self, ofc_network_id, description):
        if self.autocheck:
            if ofc_network_id not in self.ofc_network_dict:
                raise Exception(_('(update_network) OFC network %s not found')
                                % ofc_network_id)
        data = {'description': description}
        self.ofc_network_dict[ofc_network_id].update(data)
        LOG.debug(_('update_network: SUCCEED'))

    @call_log.log
    def delete_network(self, ofc_network_id):
        if ofc_network_id in self.ofc_network_dict:
            del self.ofc_network_dict[ofc_network_id]
        else:
            if self.autocheck:
                raise Exception(_('(delete_network) OFC network %s not found')
                                % ofc_network_id)
        LOG.debug(_('delete_network: SUCCEED'))

    @call_log.log
    def create_port(self, ofc_network_id, info, port_id=None, filters=None):
        ofc_id = "ofc-" + port_id[:-4]
        if self.autocheck:
            if ofc_network_id not in self.ofc_network_dict:
                raise Exception(_('(create_port) OFC network %s not found')
                                % ofc_network_id)
            if ofc_id in self.ofc_port_dict:
                raise Exception(_('(create_port) OFC port %s already exists')
                                % ofc_id)
        self.ofc_port_dict[ofc_id] = {'network_id': ofc_network_id,
                                      'port_id': port_id}
        if filters:
            self.ofc_port_dict[ofc_id]['filters'] = filters
        return ofc_id

    @call_log.log
    def delete_port(self, ofc_port_id):
        if ofc_port_id in self.ofc_port_dict:
            del self.ofc_port_dict[ofc_port_id]
        else:
            if self.autocheck:
                raise Exception(_('(delete_port) OFC port %s not found')
                                % ofc_port_id)
        LOG.debug(_('delete_port: SUCCEED'))

    @classmethod
    def filter_supported(cls):
        return True

    def create_filter(self, ofc_network_id, filter_dict,
                      portinfo=None, filter_id=None, apply_ports=None):
        return "ofc-" + filter_id[:-4]

    def delete_filter(self, ofc_filter_id):
        pass

    def convert_ofc_tenant_id(self, context, ofc_tenant_id):
        return ofc_tenant_id

    def convert_ofc_network_id(self, context, ofc_network_id, tenant_id):
        return ofc_network_id

    def convert_ofc_port_id(self, context, ofc_port_id, tenant_id, network_id):
        return ofc_port_id

    def convert_ofc_filter_id(self, context, ofc_filter_id):
        return ofc_filter_id

    router_supported = True
    router_nat_supported = True

    @call_log.log
    def create_router(self, ofc_tenant_id, router_id, description):
        ofc_id = "ofc-" + router_id[:-4]
        if self.autocheck:
            if ofc_tenant_id not in self.ofc_tenant_dict:
                raise Exception(_('(create_router) OFC tenant %s not found')
                                % ofc_tenant_id)
            if ofc_id in self.ofc_router_dict:
                raise Exception(_('(create_router) OFC router %s '
                                  'already exists') % ofc_id)
        if len(self.ofc_router_dict) >= MAX_NUM_OPENFLOW_ROUTER:
            params = {'reason': _("Operation on OFC is failed"),
                      'status': 409}
            raise nexc.OFCException(**params)
        self.ofc_router_dict[ofc_id] = {'tenant_id': ofc_tenant_id,
                                        'router_id': router_id,
                                        'description': description}
        return ofc_id

    @call_log.log
    def delete_router(self, ofc_router_id):
        if ofc_router_id in self.ofc_router_dict:
            del self.ofc_router_dict[ofc_router_id]
        else:
            if self.autocheck:
                raise Exception(_('(delete_router) OFC router %s not found')
                                % ofc_router_id)
        LOG.debug(_('delete_router: SUCCEED'))

    @call_log.log
    def add_router_interface(self, ofc_router_id, ofc_net_id,
                             ip_address=None, mac_address=None):
        if_id = "ofc-" + uuidutils.generate_uuid()[:-4]
        # IP address should have a format of a.b.c.d/N
        if ip_address != str(netaddr.IPNetwork(ip_address)):
            raise Exception(_('(add_router_interface) '
                            'ip_address %s is not a valid format (a.b.c.d/N).')
                            % ip_address)
        if self.autocheck:
            if ofc_router_id not in self.ofc_router_dict:
                raise Exception(_('(add_router_interface) '
                                  'OFC router %s not found') % ofc_router_id)
            if ofc_net_id not in self.ofc_network_dict:
                raise Exception(_('(add_router_interface) '
                                  'OFC network %s not found') % ofc_net_id)
            # Check duplicate destination
        self.ofc_router_inf_dict[if_id] = {'router_id': ofc_router_id,
                                           'network_id': ofc_net_id,
                                           'ip_address': ip_address,
                                           'mac_address': mac_address}
        LOG.debug(_('add_router_interface: SUCCEED (if_id=%s)'), if_id)
        return if_id

    @call_log.log
    def update_router_interface(self, ofc_router_inf_id,
                                ip_address=None, mac_address=None):
        if ofc_router_inf_id not in self.ofc_router_inf_dict:
            if self.autocheck:
                raise Exception(_('(delete_router_interface) '
                                  'OFC router interface %s not found')
                                % ofc_router_inf_id)
            self.ofc_router_inf_dict[ofc_router_inf_id] = {}
        inf = self.ofc_router_inf_dict[ofc_router_inf_id]
        if ip_address:
            inf.update({'ip_address': ip_address})
        if mac_address:
            inf.update({'mac_address': mac_address})
        LOG.debug(_('update_router_route: SUCCEED'))

    @call_log.log
    def delete_router_interface(self, ofc_router_inf_id):
        if ofc_router_inf_id in self.ofc_router_inf_dict:
            del self.ofc_router_inf_dict[ofc_router_inf_id]
        else:
            if self.autocheck:
                raise Exception(_('(delete_router_interface) '
                                  'OFC router interface %s not found')
                                % ofc_router_inf_id)
        LOG.debug(_('delete_router_interface: SUCCEED'))

    @call_log.log
    def add_router_route(self, ofc_router_id, destination, nexthop):
        route_id = "ofc-" + uuidutils.generate_uuid()[:-4]
        # IP address format check
        netaddr.IPNetwork(destination)
        netaddr.IPAddress(nexthop)
        if self.autocheck:
            if ofc_router_id not in self.ofc_router_dict:
                raise Exception(_('(add_router_route) OFC router %s not found')
                                % ofc_router_id)
            # Check duplicate destination
            if destination in [route['destination'] for route in
                               self.ofc_router_route_dict.values()]:
                raise Exception(_('(add_router_route) '
                                'route to "%s" already exists') % destination)
        self.ofc_router_route_dict[route_id] = {'router_id': ofc_router_id,
                                                'destination': destination,
                                                'nexthop': nexthop}
        LOG.debug(_('add_router_route: SUCCEED (route_id=%s)'), route_id)
        return route_id

    @call_log.log
    def delete_router_route(self, ofc_router_route_id):
        if ofc_router_route_id in self.ofc_router_route_dict:
            del self.ofc_router_route_dict[ofc_router_route_id]
        else:
            if self.autocheck:
                raise Exception(_('(delete_router_route) OFC router route %s '
                                  'not found') % ofc_router_route_id)
        LOG.debug(_('delete_router_route: SUCCEED'))

    @call_log.log
    def list_router_routes(self, ofc_router_id):
        if self.autocheck:
            if ofc_router_id not in self.ofc_router_dict:
                raise Exception(_('(delete_router) OFC router %s not found')
                                % ofc_router_id)
        routes = [{'id': k,
                   'destination': v['destination'],
                   'nexthop': v['nexthop']}
                  for k, v in self.ofc_router_route_dict.items()
                  if v['router_id'] == ofc_router_id]
        LOG.debug(_('list_router_routes: routes=%s'), routes)
        return routes
