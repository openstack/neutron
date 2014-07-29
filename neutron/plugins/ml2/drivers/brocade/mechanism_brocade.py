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
# Author:
# Shiv Haris (shivharis@hotmail.com)


"""Implentation of Brocade ML2 Mechanism driver for ML2 Plugin."""

from oslo.config import cfg

from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.ml2 import driver_api
from neutron.plugins.ml2.drivers.brocade.db import models as brocade_db

LOG = logging.getLogger(__name__)
MECHANISM_VERSION = 0.9
NOS_DRIVER = 'neutron.plugins.ml2.drivers.brocade.nos.nosdriver.NOSdriver'

ML2_BROCADE = [cfg.StrOpt('address', default='',
                          help=_('The address of the host to SSH to')),
               cfg.StrOpt('username', default='admin',
                          help=_('The SSH username to use')),
               cfg.StrOpt('password', default='password', secret=True,
                          help=_('The SSH password to use')),
               cfg.StrOpt('physical_networks', default='',
                          help=_('Allowed physical networks')),
               cfg.StrOpt('ostype', default='NOS',
                          help=_('OS Type of the switch')),
               cfg.StrOpt('osversion', default='4.0.0',
                          help=_('OS Version number'))
               ]

cfg.CONF.register_opts(ML2_BROCADE, "ml2_brocade")


class BrocadeMechanism(driver_api.MechanismDriver):
    """ML2 Mechanism driver for Brocade VDX switches. This is the upper
    layer driver class that interfaces to lower layer (NETCONF) below.

    """

    def __init__(self):
        self._driver = None
        self._physical_networks = None
        self._switch = None
        self.initialize()

    def initialize(self):
        """Initilize of variables needed by this class."""

        self._physical_networks = cfg.CONF.ml2_brocade.physical_networks
        self.brocade_init()

    def brocade_init(self):
        """Brocade specific initialization for this class."""

        osversion = None
        self._switch = {
            'address': cfg.CONF.ml2_brocade.address,
            'username': cfg.CONF.ml2_brocade.username,
            'password': cfg.CONF.ml2_brocade.password,
            'ostype': cfg.CONF.ml2_brocade.ostype,
            'osversion': cfg.CONF.ml2_brocade.osversion}

        self._driver = importutils.import_object(NOS_DRIVER)

        # Detect version of NOS on the switch
        osversion = self._switch['osversion']
        if osversion == "autodetect":
            osversion = self._driver.get_nos_version(
                self._switch['address'],
                self._switch['username'],
                self._switch['password'])

        virtual_fabric_enabled = self._driver.is_virtual_fabric_enabled(
            self._switch['address'],
            self._switch['username'],
            self._switch['password'])

        if virtual_fabric_enabled:
            LOG.debug(_("Virtual Fabric: enabled"))
        else:
            LOG.debug(_("Virtual Fabric: not enabled"))

        self.set_features_enabled(osversion, virtual_fabric_enabled)

    def set_features_enabled(self, nos_version, virtual_fabric_enabled):
        self._virtual_fabric_enabled = virtual_fabric_enabled
        version = nos_version.split(".", 2)

        # Starting 4.1.0 port profile domains are supported
        if int(version[0]) >= 5 or (int(version[0]) >= 4
                                    and int(version[1]) >= 1):
            self._pp_domains_supported = True
        else:
            self._pp_domains_supported = False
        self._driver.set_features_enabled(self._pp_domains_supported,
                                          self._virtual_fabric_enabled)

    def get_features_enabled(self):
        return self._pp_domains_supported, self._virtual_fabric_enabled

    def create_network_precommit(self, mech_context):
        """Create Network in the mechanism specific database table."""

        network = mech_context.current
        context = mech_context._plugin_context
        tenant_id = network['tenant_id']
        network_id = network['id']

        segments = mech_context.network_segments
        # currently supports only one segment per network
        segment = segments[0]

        network_type = segment['network_type']
        vlan_id = segment['segmentation_id']
        segment_id = segment['id']

        if segment['physical_network'] not in self._physical_networks:
            raise Exception(
                _("Brocade Mechanism: failed to create network, "
                  "network cannot be created in the configured "
                  "physical network"))

        if network_type != 'vlan':
            raise Exception(
                _("Brocade Mechanism: failed to create network, "
                  "only network type vlan is supported"))

        try:
            brocade_db.create_network(context, network_id, vlan_id,
                                      segment_id, network_type, tenant_id)
        except Exception:
            LOG.exception(
                _("Brocade Mechanism: failed to create network in db"))
            raise Exception(
                _("Brocade Mechanism: create_network_precommit failed"))

        LOG.info(_("create network (precommit): %(network_id)s "
                   "of network type = %(network_type)s "
                   "with vlan = %(vlan_id)s "
                   "for tenant %(tenant_id)s"),
                 {'network_id': network_id,
                  'network_type': network_type,
                  'vlan_id': vlan_id,
                  'tenant_id': tenant_id})

    def create_network_postcommit(self, mech_context):
        """Create Network as a portprofile on the switch."""

        LOG.debug(_("create_network_postcommit: called"))

        network = mech_context.current
        # use network_id to get the network attributes
        # ONLY depend on our db for getting back network attributes
        # this is so we can replay postcommit from db
        context = mech_context._plugin_context

        network_id = network['id']
        network = brocade_db.get_network(context, network_id)
        network_type = network['network_type']
        tenant_id = network['tenant_id']
        vlan_id = network['vlan']

        try:
            self._driver.create_network(self._switch['address'],
                                        self._switch['username'],
                                        self._switch['password'],
                                        vlan_id)
        except Exception:
            LOG.exception(_("Brocade NOS driver: failed in create network"))
            brocade_db.delete_network(context, network_id)
            raise Exception(
                _("Brocade Mechanism: create_network_postcommmit failed"))

        LOG.info(_("created network (postcommit): %(network_id)s"
                   " of network type = %(network_type)s"
                   " with vlan = %(vlan_id)s"
                   " for tenant %(tenant_id)s"),
                 {'network_id': network_id,
                  'network_type': network_type,
                  'vlan_id': vlan_id,
                  'tenant_id': tenant_id})

    def delete_network_precommit(self, mech_context):
        """Delete Network from the plugin specific database table."""

        LOG.debug(_("delete_network_precommit: called"))

        network = mech_context.current
        network_id = network['id']
        vlan_id = network['provider:segmentation_id']
        tenant_id = network['tenant_id']

        context = mech_context._plugin_context

        try:
            brocade_db.delete_network(context, network_id)
        except Exception:
            LOG.exception(
                _("Brocade Mechanism: failed to delete network in db"))
            raise Exception(
                _("Brocade Mechanism: delete_network_precommit failed"))

        LOG.info(_("delete network (precommit): %(network_id)s"
                   " with vlan = %(vlan_id)s"
                   " for tenant %(tenant_id)s"),
                 {'network_id': network_id,
                  'vlan_id': vlan_id,
                  'tenant_id': tenant_id})

    def delete_network_postcommit(self, mech_context):
        """Delete network which translates to removng portprofile
        from the switch.
        """

        LOG.debug(_("delete_network_postcommit: called"))
        network = mech_context.current
        network_id = network['id']
        vlan_id = network['provider:segmentation_id']
        tenant_id = network['tenant_id']

        try:
            self._driver.delete_network(self._switch['address'],
                                        self._switch['username'],
                                        self._switch['password'],
                                        vlan_id)
        except Exception:
            LOG.exception(_("Brocade NOS driver: failed to delete network"))
            raise Exception(
                _("Brocade switch exception, "
                  "delete_network_postcommit failed"))

        LOG.info(_("delete network (postcommit): %(network_id)s"
                   " with vlan = %(vlan_id)s"
                   " for tenant %(tenant_id)s"),
                 {'network_id': network_id,
                  'vlan_id': vlan_id,
                  'tenant_id': tenant_id})

    def update_network_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        pass

    def update_network_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        pass

    def create_port_precommit(self, mech_context):
        """Create logical port on the switch (db update)."""

        LOG.debug(_("create_port_precommit: called"))

        port = mech_context.current
        port_id = port['id']
        network_id = port['network_id']
        tenant_id = port['tenant_id']
        admin_state_up = port['admin_state_up']

        context = mech_context._plugin_context

        network = brocade_db.get_network(context, network_id)
        vlan_id = network['vlan']

        try:
            brocade_db.create_port(context, port_id, network_id,
                                   None,
                                   vlan_id, tenant_id, admin_state_up)
        except Exception:
            LOG.exception(_("Brocade Mechanism: failed to create port in db"))
            raise Exception(
                _("Brocade Mechanism: create_port_precommit failed"))

    def create_port_postcommit(self, mech_context):
        """Associate the assigned MAC address to the portprofile."""

        LOG.debug(_("create_port_postcommit: called"))

        port = mech_context.current
        port_id = port['id']
        network_id = port['network_id']
        tenant_id = port['tenant_id']

        context = mech_context._plugin_context

        network = brocade_db.get_network(context, network_id)
        vlan_id = network['vlan']

        interface_mac = port['mac_address']

        # convert mac format: xx:xx:xx:xx:xx:xx -> xxxx.xxxx.xxxx
        mac = self.mac_reformat_62to34(interface_mac)
        try:
            self._driver.associate_mac_to_network(self._switch['address'],
                                                  self._switch['username'],
                                                  self._switch['password'],
                                                  vlan_id,
                                                  mac)
        except Exception:
            LOG.exception(
                _("Brocade NOS driver: failed to associate mac %s")
                % interface_mac)
            raise Exception(
                _("Brocade switch exception: create_port_postcommit failed"))

        LOG.info(
            _("created port (postcommit): port_id=%(port_id)s"
              " network_id=%(network_id)s tenant_id=%(tenant_id)s"),
            {'port_id': port_id,
             'network_id': network_id, 'tenant_id': tenant_id})

    def delete_port_precommit(self, mech_context):
        """Delete logical port on the switch (db update)."""

        LOG.debug(_("delete_port_precommit: called"))
        port = mech_context.current
        port_id = port['id']

        context = mech_context._plugin_context

        try:
            brocade_db.delete_port(context, port_id)
        except Exception:
            LOG.exception(_("Brocade Mechanism: failed to delete port in db"))
            raise Exception(
                _("Brocade Mechanism: delete_port_precommit failed"))

    def delete_port_postcommit(self, mech_context):
        """Dissociate MAC address from the portprofile."""

        LOG.debug(_("delete_port_postcommit: called"))
        port = mech_context.current
        port_id = port['id']
        network_id = port['network_id']
        tenant_id = port['tenant_id']

        context = mech_context._plugin_context

        network = brocade_db.get_network(context, network_id)
        vlan_id = network['vlan']

        interface_mac = port['mac_address']

        # convert mac format: xx:xx:xx:xx:xx:xx -> xxxx.xxxx.xxxx
        mac = self.mac_reformat_62to34(interface_mac)
        try:
            self._driver.dissociate_mac_from_network(
                self._switch['address'],
                self._switch['username'],
                self._switch['password'],
                vlan_id,
                mac)
        except Exception:
            LOG.exception(
                _("Brocade NOS driver: failed to dissociate MAC %s") %
                interface_mac)
            raise Exception(
                _("Brocade switch exception, delete_port_postcommit failed"))

        LOG.info(
            _("delete port (postcommit): port_id=%(port_id)s"
              " network_id=%(network_id)s tenant_id=%(tenant_id)s"),
            {'port_id': port_id,
             'network_id': network_id, 'tenant_id': tenant_id})

    def update_port_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("update_port_precommit(self: called"))

    def update_port_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("update_port_postcommit: called"))

    def create_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("create_subnetwork_precommit: called"))

    def create_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("create_subnetwork_postcommit: called"))

    def delete_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("delete_subnetwork_precommit: called"))

    def delete_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("delete_subnetwork_postcommit: called"))

    def update_subnet_precommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("update_subnet_precommit(self: called"))

    def update_subnet_postcommit(self, mech_context):
        """Noop now, it is left here for future."""
        LOG.debug(_("update_subnet_postcommit: called"))

    @staticmethod
    def mac_reformat_62to34(interface_mac):
        """Transform MAC address format.

        Transforms from 6 groups of 2 hexadecimal numbers delimited by ":"
        to 3 groups of 4 hexadecimals numbers delimited by ".".

        :param interface_mac: MAC address in the format xx:xx:xx:xx:xx:xx
        :type interface_mac: string
        :returns: MAC address in the format xxxx.xxxx.xxxx
        :rtype: string
        """

        mac = interface_mac.replace(":", "")
        mac = mac[0:4] + "." + mac[4:8] + "." + mac[8:12]
        return mac
