# Copyright 2013 NEC Corporation.  All rights reserved.
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

import abc
import httplib

import six

from neutron.common import log as call_log
from neutron.common import utils
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.nec.common import constants as nconst
from neutron.plugins.nec.common import exceptions as nexc

LOG = logging.getLogger(__name__)

PROVIDER_OPENFLOW = nconst.ROUTER_PROVIDER_OPENFLOW


@six.add_metaclass(abc.ABCMeta)
class RouterDriverBase(object):

    def __init__(self, plugin, ofc_manager):
        self.plugin = plugin
        self.ofc = ofc_manager

    def floating_ip_support(self):
        return True

    @abc.abstractmethod
    def create_router(self, context, tenant_id, router):
        pass

    @abc.abstractmethod
    def update_router(self, context, router_id, old_router, new_router):
        pass

    @abc.abstractmethod
    def delete_router(self, context, router_id, router):
        pass

    @abc.abstractmethod
    def add_interface(self, context, router_id, port):
        pass

    @abc.abstractmethod
    def delete_interface(self, context, router_id, port):
        pass


class RouterL3AgentDriver(RouterDriverBase):

    need_gw_info = False

    @call_log.log
    def create_router(self, context, tenant_id, router):
        return router

    @call_log.log
    def update_router(self, context, router_id, old_router, new_router):
        return new_router

    @call_log.log
    def delete_router(self, context, router_id, router):
        pass

    @call_log.log
    def add_interface(self, context, router_id, port):
        return self.plugin.activate_port_if_ready(context, port)

    @call_log.log
    def delete_interface(self, context, router_id, port):
        return self.plugin.deactivate_port(context, port)


class RouterOpenFlowDriver(RouterDriverBase):

    need_gw_info = True

    def floating_ip_support(self):
        return self.ofc.driver.router_nat_supported

    def _process_gw_port(self, gw_info, routes):
        if gw_info and gw_info['gateway_ip']:
            routes.append({'destination': '0.0.0.0/0',
                           'nexthop': gw_info['gateway_ip']})

    @call_log.log
    def create_router(self, context, tenant_id, router):
        try:
            router_id = router['id']
            added_routes = []
            self.ofc.ensure_ofc_tenant(context, tenant_id)
            self.ofc.create_ofc_router(context, tenant_id, router_id,
                                       router['name'])
            self._process_gw_port(router['gw_port'], added_routes)
            if added_routes:
                self.ofc.update_ofc_router_route(context, router_id,
                                                 added_routes, [])
            new_status = nconst.ROUTER_STATUS_ACTIVE
            self.plugin._update_resource_status(context, "router",
                                                router['id'],
                                                new_status)
            router['status'] = new_status
            return router
        except (nexc.OFCException, nexc.OFCMappingNotFound) as exc:
            with excutils.save_and_reraise_exception():
                if (isinstance(exc, nexc.OFCException) and
                    exc.status == httplib.CONFLICT):
                    raise nexc.RouterOverLimit(provider=PROVIDER_OPENFLOW)
                reason = _("create_router() failed due to %s") % exc
                LOG.error(reason)
                new_status = nconst.ROUTER_STATUS_ERROR
                self._update_resource_status(context, "router",
                                             router['id'],
                                             new_status)

    @call_log.log
    def update_router(self, context, router_id, old_router, new_router):
        old_routes = old_router['routes'][:]
        new_routes = new_router['routes'][:]
        self._process_gw_port(old_router['gw_port'], old_routes)
        self._process_gw_port(new_router['gw_port'], new_routes)
        added, removed = utils.diff_list_of_dict(old_routes, new_routes)
        if added or removed:
            try:
                # NOTE(amotoki): PFC supports one-by-one route update at now.
                # It means there may be a case where some route is updated but
                # some not. To allow the next call of failures to sync routes
                # with Neutron side, we pass the whole new routes here.
                # PFC should support atomic route update in the future.
                self.ofc.update_ofc_router_route(context, router_id,
                                                 new_routes)
                new_status = nconst.ROUTER_STATUS_ACTIVE
                self.plugin._update_resource_status(
                    context, "router", router_id, new_status)
                new_router['status'] = new_status
            except (nexc.OFCException, nexc.OFCMappingNotFound) as exc:
                with excutils.save_and_reraise_exception():
                    reason = _("_update_ofc_routes() failed due to %s") % exc
                    LOG.error(reason)
                    new_status = nconst.ROUTER_STATUS_ERROR
                    self.plugin._update_resource_status(
                        context, "router", router_id, new_status)
        return new_router

    @call_log.log
    def delete_router(self, context, router_id, router):
        if not self.ofc.exists_ofc_router(context, router_id):
            return
        try:
            self.ofc.delete_ofc_router(context, router_id, router)
        except (nexc.OFCException, nexc.OFCMappingNotFound) as exc:
            with excutils.save_and_reraise_exception():
                LOG.error(_("delete_router() failed due to %s"), exc)
                self.plugin._update_resource_status(
                    context, "router", router_id, nconst.ROUTER_STATUS_ERROR)

    @call_log.log
    def add_interface(self, context, router_id, port):
        port_id = port['id']
        # port['fixed_ips'] may be empty if ext_net has no subnet.
        # Such port is invalid for a router port and we don't create a port
        # on OFC. The port is removed in l3_db._create_router_gw_port.
        if not port['fixed_ips']:
            msg = _('RouterOpenFlowDriver.add_interface(): the requested port '
                    'has no subnet. add_interface() is skipped. '
                    'router_id=%(id)s, port=%(port)s)')
            LOG.warning(msg, {'id': router_id, 'port': port})
            return port
        fixed_ip = port['fixed_ips'][0]
        subnet = self.plugin._get_subnet(context, fixed_ip['subnet_id'])
        port_info = {'network_id': port['network_id'],
                     'ip_address': fixed_ip['ip_address'],
                     'cidr': subnet['cidr'],
                     'mac_address': port['mac_address']}
        try:
            self.ofc.add_ofc_router_interface(context, router_id,
                                              port_id, port_info)
            new_status = nconst.ROUTER_STATUS_ACTIVE
            self.plugin._update_resource_status(
                context, "port", port_id, new_status)
            return port
        except (nexc.OFCException, nexc.OFCMappingNotFound) as exc:
            with excutils.save_and_reraise_exception():
                reason = _("add_router_interface() failed due to %s") % exc
                LOG.error(reason)
                new_status = nconst.ROUTER_STATUS_ERROR
                self.plugin._update_resource_status(
                    context, "port", port_id, new_status)

    @call_log.log
    def delete_interface(self, context, router_id, port):
        port_id = port['id']
        try:
            self.ofc.delete_ofc_router_interface(context, router_id, port_id)
            new_status = nconst.ROUTER_STATUS_ACTIVE
            self.plugin._update_resource_status(context, "port", port_id,
                                                new_status)
            port['status'] = new_status
            return port
        except (nexc.OFCException, nexc.OFCMappingNotFound) as exc:
            with excutils.save_and_reraise_exception():
                reason = _("delete_router_interface() failed due to %s") % exc
                LOG.error(reason)
                new_status = nconst.ROUTER_STATUS_ERROR
                self.plugin._update_resource_status(context, "port", port_id,
                                                    new_status)
