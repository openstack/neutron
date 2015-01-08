# Copyright 2014 Brocade Communications System, Inc.
# All rights reserved.
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


"""Implentation of Brocade SVI service Plugin."""

from oslo_config import cfg
from oslo_utils import excutils

from neutron.common import constants as l3_constants
from neutron.i18n import _LE, _LI
from neutron.openstack.common import log as logging
from neutron.plugins.ml2 import db
from neutron.plugins.ml2.drivers.brocade.db import models as brocade_db
from neutron.plugins.ml2.drivers.brocade.nos import nosdriver as driver
from neutron.services.l3_router import l3_router_plugin as router


DEVICE_OWNER_ROUTER_INTF = l3_constants.DEVICE_OWNER_ROUTER_INTF
DEVICE_OWNER_ROUTER_GW = l3_constants.DEVICE_OWNER_ROUTER_GW
DEVICE_OWNER_FLOATINGIP = l3_constants.DEVICE_OWNER_FLOATINGIP

ML2_BROCADE = [cfg.StrOpt('address', default='',
                          help=_('The address of the host to SSH to')),
               cfg.StrOpt('username', default='admin',
                          help=_('The SSH username to use')),
               cfg.StrOpt('password', default='password', secret=True,
                          help=_('The SSH password to use')),
               cfg.StrOpt('rbridge_id', default=1,
                          help=_('Rbridge id of provider edge router(s)')),
               ]

cfg.CONF.register_opts(ML2_BROCADE, "ml2_brocade")

LOG = logging.getLogger(__name__)


class BrocadeSVIPlugin(router.L3RouterPlugin):
    """Brocade SVI service Plugin."""

    def __init__(self):
        """Initialize Brocade Plugin

        Specify switch address and db configuration.
        """
        super(BrocadeSVIPlugin, self).__init__()
        self._switch = None
        self._driver = None
        self.brocade_init()

    def brocade_init(self):
        """Brocade specific initialization."""
        LOG.debug("brocadeSVIPlugin::brocade_init()")

        self._switch = {'address': cfg.CONF.ml2_brocade.address,
                        'username': cfg.CONF.ml2_brocade.username,
                        'password': cfg.CONF.ml2_brocade.password,
                        'rbridge_id': cfg.CONF.ml2_brocade.rbridge_id
                        }
        self._driver = driver.NOSdriver()
        LOG.info(_LI("rbridge id %s"), self._switch['rbridge_id'])

    def create_router(self, context, router):
        """Creates a vrf on NOS device."""
        LOG.debug("BrocadeSVIPlugin.create_router called: ")
        with context.session.begin(subtransactions=True):
            new_router = super(BrocadeSVIPlugin, self).create_router(context,
                                                                     router)
            # Router on VDX
            try:
                switch = self._switch
                self._driver.create_router(switch['address'],
                                           switch['username'],
                                           switch['password'],
                                           switch['rbridge_id'],
                                           str(new_router['id']))
            except Exception:
                with excutils.save_and_reraise_exception():
                    with context.session.begin(subtransactions=True):
                        super(BrocadeSVIPlugin, self).delete_router(
                            context,
                            new_router['id'])

        LOG.debug("BrocadeSVIPlugin.create_router: "
                  "router created on VDX switch")
        return new_router

    def delete_router(self, context, router_id):
        """Delete a vrf on NOS device."""
        router = super(BrocadeSVIPlugin, self).get_router(context, router_id)
        super(BrocadeSVIPlugin, self).delete_router(context, router_id)

        switch = self._switch
        self._driver.delete_router(switch['address'],
                                   switch['username'],
                                   switch['password'],
                                   switch['rbridge_id'],
                                   str(router['id']))

    def add_router_interface(self, context, router_id, interface_info):
        """creates svi on NOS device and assigns ip addres to SVI."""
        LOG.debug("BrocadeSVIPlugin.add_router_interface on VDX: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})

        with context.session.begin(subtransactions=True):

            info = super(BrocadeSVIPlugin, self).add_router_interface(
                context, router_id, interface_info)

            port = db.get_port(context.session, info["port_id"])

            # shutting down neutron port to allow NOS to do Arp/Routing
            port['admin_state_up'] = False
            port['port'] = port
            self._core_plugin.update_port(context, info["port_id"], port)

            interface_info = info
            subnet = self._core_plugin._get_subnet(context,
                                                   interface_info["subnet_id"])
            cidr = subnet["cidr"]
            net_addr, net_len = self.net_addr(cidr)
            gateway_ip = subnet["gateway_ip"]
            network_id = subnet['network_id']
            bnet = brocade_db.get_network(context, network_id)
            vlan_id = bnet['vlan']
            gateway_ip_cidr = gateway_ip + '/' + str(net_len)
            LOG.debug("Allocated cidr %(cidr)s from the pool, "
                      "network_id %(net_id)s "
                      "bnet %(bnet)s "
                      "vlan %(vlan_id)d ", {'cidr': gateway_ip_cidr,
                                            'net_id': network_id,
                                            'bnet': bnet,
                                            'vlan_id': int(vlan_id)})
            port_filters = {'network_id': [network_id],
                            'device_owner': [DEVICE_OWNER_ROUTER_INTF]}
            port_count = self._core_plugin.get_ports_count(context,
                                                           port_filters)
            LOG.info(_LI("BrocadeSVIPlugin.add_router_interface ports_count "
                         "%d"),
                     port_count)

            # port count is checked against 2 since the current port is already
            # added to db
            if port_count == 2:
                # This subnet is already part of some router
                # (this is not supported in this version of brocade svi plugin)
                msg = _("BrocadeSVIPlugin: adding redundant router interface "
                        "is not supported")
                LOG.error(msg)
                raise Exception(msg)

        try:
            switch = self._switch
            self._driver.create_svi(switch['address'],
                                    switch['username'],
                                    switch['password'],
                                    switch['rbridge_id'],
                                    vlan_id,
                                    gateway_ip_cidr,
                                    str(router_id))
        except Exception:
            LOG.error(_LE("Failed to create Brocade resources to add router "
                          "interface. info=%(info)s, router_id=%(router_id)s"),
                      {"info": info, "router_id": router_id})
            with excutils.save_and_reraise_exception():
                with context.session.begin(subtransactions=True):
                    self.remove_router_interface(context, router_id,
                                                 interface_info)
        return info

    def remove_router_interface(self, context, router_id, interface_info):
        """Deletes svi from NOS device."""
        LOG.debug("BrocadeSVIPlugin.remove_router_interface called: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})

        with context.session.begin(subtransactions=True):
            info = super(BrocadeSVIPlugin, self).remove_router_interface(
                context, router_id, interface_info)
            try:
                subnet = self._core_plugin._get_subnet(context,
                                                       info['subnet_id'])
                cidr = subnet['cidr']
                net_addr, net_len = self.net_addr(cidr)
                gateway_ip = subnet['gateway_ip']
                network_id = subnet['network_id']
                bnet = brocade_db.get_network(context, network_id)
                vlan_id = bnet['vlan']
                gateway_ip_cidr = gateway_ip + '/' + str(net_len)
                LOG.debug("remove_router_interface removed cidr %(cidr)s"
                          " from the pool,"
                          " network_id %(net_id)s bnet %(bnet)s"
                          " vlan %(vlan_id)d",
                          {'cidr': gateway_ip_cidr,
                           'net_id': network_id,
                           'bnet': bnet,
                           'vlan_id': int(vlan_id)})
                switch = self._switch
                self._driver.delete_svi(switch['address'],
                                        switch['username'],
                                        switch['password'],
                                        switch['rbridge_id'],
                                        vlan_id,
                                        gateway_ip_cidr,
                                        str(router_id))
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.error(_LE("Fail remove of interface from brocade "
                                  "router interface. info=%(info)s, "
                                  "router_id=%(router_id)s"),
                              {"info": info, "router_id": router_id})
        return True

    @staticmethod
    def net_addr(addr):
        """Get network address prefix and length from a given address."""
        if addr is None:
            return None, None
        nw_addr, nw_len = addr.split('/')
        nw_len = int(nw_len)
        return nw_addr, nw_len
