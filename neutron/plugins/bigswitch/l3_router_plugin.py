# Copyright 2014 Big Switch Networks, Inc.
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

"""
Neutron L3 REST Proxy Plugin for Big Switch and Floodlight Controllers.

This plugin handles the L3 router calls for Big Switch Floodlight deployments.
It is intended to be used in conjunction with the Big Switch ML2 driver or the
Big Switch core plugin.
"""

from oslo_config import cfg
from oslo_utils import excutils

from neutron.api import extensions as neutron_extensions
from neutron.common import exceptions
from neutron.common import log
from neutron.db import l3_db
from neutron.extensions import l3
from neutron.i18n import _LE
from neutron.openstack.common import log as logging
from neutron.plugins.bigswitch import extensions
from neutron.plugins.bigswitch import plugin as cplugin
from neutron.plugins.bigswitch import routerrule_db
from neutron.plugins.bigswitch import servermanager
from neutron.plugins.common import constants

# number of fields in a router rule string
ROUTER_RULE_COMPONENT_COUNT = 5
LOG = logging.getLogger(__name__)
put_context_in_serverpool = cplugin.put_context_in_serverpool


class L3RestProxy(cplugin.NeutronRestProxyV2Base,
                  routerrule_db.RouterRule_db_mixin):

    supported_extension_aliases = ["router", "router_rules"]

    @staticmethod
    def get_plugin_type():
        return constants.L3_ROUTER_NAT

    @staticmethod
    def get_plugin_description():
        return _("L3 Router Service Plugin for Big Switch fabric")

    def __init__(self):
        # Include the Big Switch Extensions path in the api_extensions
        neutron_extensions.append_api_extensions_path(extensions.__path__)
        super(L3RestProxy, self).__init__()
        self.servers = servermanager.ServerPool.get_instance()

    @put_context_in_serverpool
    @log.log
    def create_router(self, context, router):
        self._warn_on_state_status(router['router'])

        tenant_id = self._get_tenant_id_for_create(context, router["router"])

        # set default router rules
        rules = self._get_tenant_default_router_rules(tenant_id)
        router['router']['router_rules'] = rules

        with context.session.begin(subtransactions=True):
            # create router in DB
            new_router = super(L3RestProxy, self).create_router(context,
                                                                router)
            mapped_router = self._map_state_and_status(new_router)
            self.servers.rest_create_router(tenant_id, mapped_router)

            # return created router
            return new_router

    @put_context_in_serverpool
    @log.log
    def update_router(self, context, router_id, router):
        self._warn_on_state_status(router['router'])

        orig_router = super(L3RestProxy, self).get_router(context, router_id)
        tenant_id = orig_router["tenant_id"]
        with context.session.begin(subtransactions=True):
            new_router = super(L3RestProxy,
                               self).update_router(context, router_id, router)
            router = self._map_state_and_status(new_router)
            # look up the network on this side to save an expensive query on
            # the backend controller.
            if router and router.get('external_gateway_info'):
                router['external_gateway_info']['network'] = self.get_network(
                    context.elevated(),
                    router['external_gateway_info']['network_id'])
            # update router on network controller
            self.servers.rest_update_router(tenant_id, router, router_id)

            # return updated router
            return new_router

    @put_context_in_serverpool
    @log.log
    def delete_router(self, context, router_id):
        with context.session.begin(subtransactions=True):
            orig_router = self._get_router(context, router_id)
            tenant_id = orig_router["tenant_id"]

            # Ensure that the router is not used
            router_filter = {'router_id': [router_id]}
            fips = self.get_floatingips_count(context.elevated(),
                                              filters=router_filter)
            if fips:
                raise l3.RouterInUse(router_id=router_id)

            device_owner = l3_db.DEVICE_OWNER_ROUTER_INTF
            device_filter = {'device_id': [router_id],
                             'device_owner': [device_owner]}
            ports = self.get_ports_count(context.elevated(),
                                         filters=device_filter)
            if ports:
                raise l3.RouterInUse(router_id=router_id)
            super(L3RestProxy, self).delete_router(context, router_id)

            # delete from network controller
            self.servers.rest_delete_router(tenant_id, router_id)

    @put_context_in_serverpool
    @log.log
    def add_router_interface(self, context, router_id, interface_info):
        # Validate args
        router = self._get_router(context, router_id)
        tenant_id = router['tenant_id']

        with context.session.begin(subtransactions=True):
            # create interface in DB
            new_intf_info = super(L3RestProxy,
                                  self).add_router_interface(context,
                                                             router_id,
                                                             interface_info)
            port = self._get_port(context, new_intf_info['port_id'])
            net_id = port['network_id']
            subnet_id = new_intf_info['subnet_id']
            # we will use the port's network id as interface's id
            interface_id = net_id
            intf_details = self._get_router_intf_details(context,
                                                         interface_id,
                                                         subnet_id)

            # create interface on the network controller
            self.servers.rest_add_router_interface(tenant_id, router_id,
                                                   intf_details)
            return new_intf_info

    @put_context_in_serverpool
    @log.log
    def remove_router_interface(self, context, router_id, interface_info):
        # Validate args
        router = self._get_router(context, router_id)
        tenant_id = router['tenant_id']

        # we will first get the interface identifier before deleting in the DB
        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise exceptions.BadRequest(resource='router', msg=msg)
        if 'port_id' in interface_info:
            port = self._get_port(context, interface_info['port_id'])
            interface_id = port['network_id']
        elif 'subnet_id' in interface_info:
            subnet = self._get_subnet(context, interface_info['subnet_id'])
            interface_id = subnet['network_id']
        else:
            msg = _("Either subnet_id or port_id must be specified")
            raise exceptions.BadRequest(resource='router', msg=msg)

        with context.session.begin(subtransactions=True):
            # remove router in DB
            del_ret = super(L3RestProxy,
                            self).remove_router_interface(context,
                                                          router_id,
                                                          interface_info)

            # create router on the network controller
            self.servers.rest_remove_router_interface(tenant_id, router_id,
                                                      interface_id)
            return del_ret

    @put_context_in_serverpool
    @log.log
    def create_floatingip(self, context, floatingip):
        with context.session.begin(subtransactions=True):
            # create floatingip in DB
            new_fl_ip = super(L3RestProxy,
                              self).create_floatingip(context, floatingip)

            # create floatingip on the network controller
            try:
                if 'floatingip' in self.servers.get_capabilities():
                    self.servers.rest_create_floatingip(
                        new_fl_ip['tenant_id'], new_fl_ip)
                else:
                    self._send_floatingip_update(context)
            except servermanager.RemoteRestError as e:
                with excutils.save_and_reraise_exception():
                    LOG.error(
                        _LE("NeutronRestProxyV2: Unable to create remote "
                            "floating IP: %s"), e)
            # return created floating IP
            return new_fl_ip

    @put_context_in_serverpool
    @log.log
    def update_floatingip(self, context, id, floatingip):
        with context.session.begin(subtransactions=True):
            # update floatingip in DB
            new_fl_ip = super(L3RestProxy,
                              self).update_floatingip(context, id, floatingip)

            # update network on network controller
            if 'floatingip' in self.servers.get_capabilities():
                self.servers.rest_update_floatingip(new_fl_ip['tenant_id'],
                                                    new_fl_ip, id)
            else:
                self._send_floatingip_update(context)
            return new_fl_ip

    @put_context_in_serverpool
    @log.log
    def delete_floatingip(self, context, id):
        with context.session.begin(subtransactions=True):
            # delete floating IP in DB
            old_fip = super(L3RestProxy, self).get_floatingip(context, id)
            super(L3RestProxy, self).delete_floatingip(context, id)

            # update network on network controller
            if 'floatingip' in self.servers.get_capabilities():
                self.servers.rest_delete_floatingip(old_fip['tenant_id'], id)
            else:
                self._send_floatingip_update(context)

    @put_context_in_serverpool
    @log.log
    def disassociate_floatingips(self, context, port_id, do_notify=True):
        router_ids = super(L3RestProxy, self).disassociate_floatingips(
            context, port_id, do_notify=do_notify)
        self._send_floatingip_update(context)
        return router_ids

    # overriding method from l3_db as original method calls
    # self.delete_floatingip() which in turn calls self.delete_port() which
    # is locked with 'bsn-port-barrier'
    @put_context_in_serverpool
    def delete_disassociated_floatingips(self, context, network_id):
        query = self._model_query(context, l3_db.FloatingIP)
        query = query.filter_by(floating_network_id=network_id,
                                fixed_port_id=None,
                                router_id=None)
        for fip in query:
            context.session.delete(fip)
            self._delete_port(context.elevated(), fip['floating_port_id'])

    def _send_floatingip_update(self, context):
        try:
            ext_net_id = self.get_external_network_id(context)
            if ext_net_id:
                # Use the elevated state of the context for the ext_net query
                admin_context = context.elevated()
                ext_net = super(L3RestProxy,
                                self).get_network(admin_context, ext_net_id)
                # update external network on network controller
                self._send_update_network(ext_net, admin_context)
        except exceptions.TooManyExternalNetworks:
            # get_external_network can raise errors when multiple external
            # networks are detected, which isn't supported by the Plugin
            LOG.error(_LE("NeutronRestProxyV2: too many external networks"))

    def _get_tenant_default_router_rules(self, tenant):
        rules = cfg.CONF.ROUTER.tenant_default_router_rule
        default_set = []
        tenant_set = []
        for rule in rules:
            items = rule.split(':')
            # put an empty string on the end if nexthops wasn't specified
            if len(items) < ROUTER_RULE_COMPONENT_COUNT:
                items.append('')
            try:
                (tenant_id, source, destination, action, nexthops) = items
            except ValueError:
                continue
            parsed_rule = {'source': source,
                           'destination': destination, 'action': action,
                           'nexthops': [hop for hop in nexthops.split(',')
                                        if hop]}
            if tenant_id == '*':
                default_set.append(parsed_rule)
            if tenant_id == tenant:
                tenant_set.append(parsed_rule)
        return tenant_set if tenant_set else default_set
