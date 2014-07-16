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
# Authors:
# Varma Bhupatiraju (vbhupati@brocade.com)
# Shiv Haris (shivharis@hotmail.com)


"""Brocade NOS Driver implements NETCONF over SSHv2 for
Neutron network life-cycle management.
"""

from ncclient import manager
from xml.etree import ElementTree

from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.brocade.nos import nctemplates as template


LOG = logging.getLogger(__name__)
SSH_PORT = 22


def nos_unknown_host_cb(host, fingerprint):
    """An unknown host callback.

    Returns `True` if it finds the key acceptable,
    and `False` if not. This default callback for NOS always returns 'True'
    (i.e. trusts all hosts for now).
    """
    return True


class NOSdriver():
    """NOS NETCONF interface driver for Neutron network.

    Handles life-cycle management of Neutron network (leverages AMPP on NOS)
    """

    def __init__(self):
        self.mgr = None
        self._virtual_fabric_enabled = False
        self._pp_domains_supported = False

    def set_features_enabled(self, pp_domains_supported,
                             virtual_fabric_enabled):
        """Set features in the driver based on what was detected by the MD."""
        self._pp_domains_supported = pp_domains_supported
        self._virtual_fabric_enabled = virtual_fabric_enabled

    def get_features_enabled(self):
        """Respond to status of features enabled."""
        return self._pp_domains_supported, self._virtual_fabric_enabled

    def connect(self, host, username, password):
        """Connect via SSH and initialize the NETCONF session."""

        # Use the persisted NETCONF connection
        if self.mgr and self.mgr.connected:
            return self.mgr

        # check if someone forgot to edit the conf file with real values
        if host == '':
            raise Exception(_("Brocade Switch IP address is not set, "
                              "check config ml2_conf_brocade.ini file"))

        # Open new NETCONF connection
        try:
            self.mgr = manager.connect(host=host, port=SSH_PORT,
                                       username=username, password=password,
                                       unknown_host_cb=nos_unknown_host_cb)

        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("Connect failed to switch"))

        LOG.debug(_("Connect success to host %(host)s:%(ssh_port)d"),
                  dict(host=host, ssh_port=SSH_PORT))
        return self.mgr

    def close_session(self):
        """Close NETCONF session."""
        if self.mgr:
            self.mgr.close_session()
            self.mgr = None

    def get_nos_version(self, host, username, password):
        """Show version of NOS."""
        try:
            mgr = self.connect(host, username, password)
            return self.nos_version_request(mgr)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
                self.close_session()

    def is_virtual_fabric_enabled(self, host, username, password):
        """Show version of NOS."""
        try:
            mgr = self.connect(host, username, password)
            return (self.virtual_fabric_info(mgr) == "enabled")
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
                self.close_session()

    def create_network(self, host, username, password, net_id):
        """Creates a new virtual network."""

        domain_name = "default"
        name = template.OS_PORT_PROFILE_NAME.format(id=net_id)
        try:
            mgr = self.connect(host, username, password)
            self.create_vlan_interface(mgr, net_id)
            self.create_port_profile(mgr, name)

            if self._pp_domains_supported and self._virtual_fabric_enabled:
                self.configure_port_profile_in_domain(mgr, domain_name, name)

            self.create_vlan_profile_for_port_profile(mgr, name)

            if self._pp_domains_supported:
                self.configure_l2_mode_for_vlan_profile_with_domains(mgr, name)
            else:
                self.configure_l2_mode_for_vlan_profile(mgr, name)

            self.configure_trunk_mode_for_vlan_profile(mgr, name)
            self.configure_allowed_vlans_for_vlan_profile(mgr, name, net_id)
            self.activate_port_profile(mgr, name)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
                self.close_session()

    def delete_network(self, host, username, password, net_id):
        """Deletes a virtual network."""

        domain_name = "default"
        name = template.OS_PORT_PROFILE_NAME.format(id=net_id)
        try:
            mgr = self.connect(host, username, password)
            if self._pp_domains_supported and self._virtual_fabric_enabled:
                self.remove_port_profile_from_domain(mgr, domain_name, name)
            self.deactivate_port_profile(mgr, name)
            self.delete_port_profile(mgr, name)
            self.delete_vlan_interface(mgr, net_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
                self.close_session()

    def associate_mac_to_network(self, host, username, password,
                                 net_id, mac):
        """Associates a MAC address to virtual network."""

        name = template.OS_PORT_PROFILE_NAME.format(id=net_id)
        try:
            mgr = self.connect(host, username, password)
            self.associate_mac_to_port_profile(mgr, name, mac)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
                self.close_session()

    def dissociate_mac_from_network(self, host, username, password,
                                    net_id, mac):
        """Dissociates a MAC address from virtual network."""

        name = template.OS_PORT_PROFILE_NAME.format(id=net_id)
        try:
            mgr = self.connect(host, username, password)
            self.dissociate_mac_from_port_profile(mgr, name, mac)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.exception(_("NETCONF error"))
                self.close_session()

    def create_vlan_interface(self, mgr, vlan_id):
        """Configures a VLAN interface."""

        confstr = template.CREATE_VLAN_INTERFACE.format(vlan_id=vlan_id)
        mgr.edit_config(target='running', config=confstr)

    def delete_vlan_interface(self, mgr, vlan_id):
        """Deletes a VLAN interface."""

        confstr = template.DELETE_VLAN_INTERFACE.format(vlan_id=vlan_id)
        mgr.edit_config(target='running', config=confstr)

    def get_port_profiles(self, mgr):
        """Retrieves all port profiles."""

        filterstr = template.PORT_PROFILE_XPATH_FILTER
        response = mgr.get_config(source='running',
                                  filter=('xpath', filterstr)).data_xml
        return response

    def get_port_profile(self, mgr, name):
        """Retrieves a port profile."""

        filterstr = template.PORT_PROFILE_NAME_XPATH_FILTER.format(name=name)
        response = mgr.get_config(source='running',
                                  filter=('xpath', filterstr)).data_xml
        return response

    def create_port_profile(self, mgr, name):
        """Creates a port profile."""

        confstr = template.CREATE_PORT_PROFILE.format(name=name)
        mgr.edit_config(target='running', config=confstr)

    def delete_port_profile(self, mgr, name):
        """Deletes a port profile."""

        confstr = template.DELETE_PORT_PROFILE.format(name=name)
        mgr.edit_config(target='running', config=confstr)

    def activate_port_profile(self, mgr, name):
        """Activates a port profile."""

        confstr = template.ACTIVATE_PORT_PROFILE.format(name=name)
        mgr.edit_config(target='running', config=confstr)

    def deactivate_port_profile(self, mgr, name):
        """Deactivates a port profile."""

        confstr = template.DEACTIVATE_PORT_PROFILE.format(name=name)
        mgr.edit_config(target='running', config=confstr)

    def associate_mac_to_port_profile(self, mgr, name, mac_address):
        """Associates a MAC address to a port profile."""

        confstr = template.ASSOCIATE_MAC_TO_PORT_PROFILE.format(
            name=name, mac_address=mac_address)
        mgr.edit_config(target='running', config=confstr)

    def dissociate_mac_from_port_profile(self, mgr, name, mac_address):
        """Dissociates a MAC address from a port profile."""

        confstr = template.DISSOCIATE_MAC_FROM_PORT_PROFILE.format(
            name=name, mac_address=mac_address)
        mgr.edit_config(target='running', config=confstr)

    def create_vlan_profile_for_port_profile(self, mgr, name):
        """Creates VLAN sub-profile for port profile."""

        confstr = template.CREATE_VLAN_PROFILE_FOR_PORT_PROFILE.format(
            name=name)
        mgr.edit_config(target='running', config=confstr)

    def configure_l2_mode_for_vlan_profile(self, mgr, name):
        """Configures L2 mode for VLAN sub-profile."""

        confstr = template.CONFIGURE_L2_MODE_FOR_VLAN_PROFILE.format(
            name=name)
        mgr.edit_config(target='running', config=confstr)

    def configure_trunk_mode_for_vlan_profile(self, mgr, name):
        """Configures trunk mode for VLAN sub-profile."""

        confstr = template.CONFIGURE_TRUNK_MODE_FOR_VLAN_PROFILE.format(
            name=name)
        mgr.edit_config(target='running', config=confstr)

    def configure_allowed_vlans_for_vlan_profile(self, mgr, name, vlan_id):
        """Configures allowed VLANs for VLAN sub-profile."""

        confstr = template.CONFIGURE_ALLOWED_VLANS_FOR_VLAN_PROFILE.format(
            name=name, vlan_id=vlan_id)
        mgr.edit_config(target='running', config=confstr)

    def remove_port_profile_from_domain(self, mgr, domain_name, name):
        """Remove port-profile from default domain."""
        confstr = template.REMOVE_PORTPROFILE_FROM_DOMAIN.format(
            domain_name=domain_name, name=name)
        mgr.edit_config(target='running', config=confstr)

    def configure_port_profile_in_domain(self, mgr, domain_name, name):
        """put port-profile in default domain."""
        confstr = template.CONFIGURE_PORTPROFILE_IN_DOMAIN.format(
            domain_name=domain_name, name=name)
        mgr.edit_config(target='running', config=confstr)

    def configure_l2_mode_for_vlan_profile_with_domains(self, mgr, name):
        """Configures L2 mode for VLAN sub-profile."""
        confstr = template.CONFIGURE_L2_MODE_FOR_VLAN_PROFILE_IN_DOMAIN.format(
            name=name)
        mgr.edit_config(target='running', config=confstr)

    def nos_version_request(self, mgr):
        """Get firmware information using NETCONF rpc."""
        reply = mgr.dispatch(template.SHOW_FIRMWARE_VERSION, None, None)
        et = ElementTree.fromstring(str(reply))
        return et.find(template.NOS_VERSION).text

    def virtual_fabric_info(self, mgr):
        """Get virtual fabric info using NETCONF get-config."""
        response = mgr.get_config('running',
                                  filter=("xpath", "/vcs/virtual-fabric"))
        et = ElementTree.fromstring(str(response))
        vfab_enable = et.find(template.VFAB_ENABLE)
        if vfab_enable is not None:
            return "enabled"
        return "disabled"
