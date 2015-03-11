# Copyright 2015 IBM Corp.
#
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

from networking_ibm.sdnve.common import exceptions as sdnve_exc
from networking_ibm.sdnve.l3plugin import sdnve_l3driver
from oslo_log import log as logging
from oslo_utils import excutils

from neutron.common import constants as q_const
from neutron.common import exceptions as n_exc
from neutron.db import db_base_plugin_v2
from neutron.db import extraroute_db
from neutron.db import l3_gwmode_db
from neutron.i18n import _LE
from neutron.plugins.common import constants as l3_constants


LOG = logging.getLogger(__name__)


class SdnveL3ServicePlugin(db_base_plugin_v2.NeutronDbPluginV2,
                   extraroute_db.ExtraRoute_db_mixin,
                   l3_gwmode_db.L3_NAT_db_mixin):

    supported_extension_aliases = ["router", "ext-gw-mode",
                                   "extraroute"]

    def __init__(self):
        self.driver = sdnve_l3driver.SdnveL3Driver()

    def get_plugin_type(self):
        return l3_constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """Returns string description of the plugin."""
        return ("SDNVE Service plugin")

    def create_router(self, context, router):
        if router['router']['admin_state_up'] is False:
            router['router']['admin_state_up'] = True
        with context.session.begin(subtransactions=True):
            new_router = super(SdnveL3ServicePlugin, self).create_router(
                context, router)
        try:
            self.driver.create_router(context, new_router)
            return new_router
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Create router failed in SDN-VE with error %s"),
                          e)
                super(SdnveL3ServicePlugin, self).delete_router(
                    context, new_router['id'])

    def update_router(self, context, id, router):
        if not router['router'].get('admin_state_up', True):
            raise n_exc.NotImplementedError(_('admin_state_up=False '
                                              'routers are not '
                                              'supported.'))
        original_router = {}
        updated_router = {}
        with context.session.begin(subtransactions=True):
            original_router = super(SdnveL3ServicePlugin, self).get_router(
                context, id)
            updated_router = super(SdnveL3ServicePlugin, self).update_router(
                context, id, router)
        try:
            self.driver.update_router(context, id, original_router, router)
            return updated_router
        except Exception as e:
            LOG.error(_LE("Update router failed in SDN-VE with error %s"),
                      e)

    def delete_router(self, context, id):
        with context.session.begin(subtransactions=True):
            super(SdnveL3ServicePlugin, self).delete_router(context, id)
        try:
            self.driver.delete_router(context, id)
        except Exception as e:
            LOG.error(_LE("Delete router operation failed in SDN-VE after "
                          "deleting the router in DB: %s"), e)

    def add_router_interface(self, context, router_id, interface_info):
        new_interface = super(SdnveL3ServicePlugin, self).add_router_interface(
            context, router_id, interface_info)
        request_info = interface_info.copy()
        request_info['port_id'] = new_interface['port_id']
        if 'subnet_id' not in interface_info:
            request_info['subnet_id'] = new_interface['subnet_id']
        try:
            self.driver.add_router_interface(context, router_id, request_info)
            return new_interface
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Update router-add-interface failed in SDN-VE "
                              "with error %s"), e)
                super(SdnveL3ServicePlugin, self).remove_router_interface(
                    context, router_id, interface_info)

    def _add_router_interface_only(self, context, router_id, interface_info):
        if interface_info.get('port_id'):
            try:
                self.driver._add_router_interface_only(context,
                                                       router_id,
                                                       interface_info)
            except Exception as e:
                LOG.error(_LE("Add interface in the rollback of a "
                              "remove_router_interface operation failed %s"),
                          e)

    def remove_router_interface(self, context, router_id, interface_info):
        subnet_id = interface_info.get('subnet_id')
        if not subnet_id:
            portid = interface_info.get('port_id')
            if not portid:
                raise sdnve_exc.BadInputException(msg=_('No port ID'))

            myport = super(SdnveL3ServicePlugin, self).\
                get_port(context, portid)
            myfixed_ips = myport.get('fixed_ips')
            if not myfixed_ips:
                raise sdnve_exc.BadInputException(msg=_('No fixed IP'))
            subnet_id = myfixed_ips[0].get('subnet_id')
            if subnet_id:
                interface_info['subnet_id'] = subnet_id
        else:
            portid = interface_info.get('port_id')
            if not portid:
                subnet = super(SdnveL3ServicePlugin, self).\
                    get_subnet(context, subnet_id)
                device_filter = {'device_id': [router_id],
                    'device_owner': [q_const.DEVICE_OWNER_ROUTER_INTF],
                    'network_id': [subnet['network_id']]}
                ports = super(SdnveL3ServicePlugin, self).get_ports(context,
                                                   filters=device_filter)
                if ports:
                    portid = ports[0]['id']
                    interface_info['port_id'] = portid
        with context.session.begin(subtransactions=True):
            info = super(SdnveL3ServicePlugin, self).remove_router_interface(
                        context, router_id, interface_info)
        try:
            self.driver.remove_router_interface(context,
                                                router_id,
                                                interface_info)
            return info
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Update router-remove-interface"
                          " failed : %s"), e)
                self._add_router_interface_only(context,
                                                router_id, interface_info)

    def create_floatingip(self, context, floatingip):
        with context.session.begin(subtransactions=True):
            new_floatingip = super(SdnveL3ServicePlugin,
                self).create_floatingip(context, floatingip)
        try:
            self.driver.create_floatingip(context, new_floatingip)
            return new_floatingip
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Create floating ip failed with error %s"), e)
                super(SdnveL3ServicePlugin, self).delete_floatingip(
                    context, new_floatingip['id'])

    def update_floatingip(self, context, id, floatingip):
        with context.session.begin(subtransactions=True):
            original_floatingip = super(
                SdnveL3ServicePlugin, self).get_floatingip(context, id)
            updated_floatingip = super(
                SdnveL3ServicePlugin, self).update_floatingip(
                    context, id, floatingip)
        try:
            self.driver.update_floatingip(context,
                                          id,
                                          original_floatingip,
                                          floatingip)
            return updated_floatingip
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Update floating ip failed with error %s"), e)
                super(SdnveL3ServicePlugin, self).update_floatingip(
                    context, id, {'floatingip': original_floatingip})

    def delete_floatingip(self, context, id):
        super(SdnveL3ServicePlugin, self).delete_floatingip(context, id)
        try:
            self.driver.delete_floatingip(context, id)
        except Exception as e:
            LOG.error(_LE("Delete floatingip failed in SDN-VE: %s"), e)
