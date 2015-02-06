# Copyright 2013 OpenStack Foundation
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

"""
Implements a Nexus-OS NETCONF over SSHv2 API Client
"""

from oslo_utils import excutils
from oslo_utils import importutils

from neutron.openstack.common import log as logging
from neutron.plugins.ml2.drivers.cisco.nexus import config as conf
from neutron.plugins.ml2.drivers.cisco.nexus import constants as const
from neutron.plugins.ml2.drivers.cisco.nexus import exceptions as cexc
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_snippets as snipp

LOG = logging.getLogger(__name__)


class CiscoNexusDriver(object):
    """Nexus Driver Main Class."""
    def __init__(self):
        self.ncclient = None
        self.nexus_switches = conf.ML2MechCiscoConfig.nexus_dict
        self.connections = {}

    def _import_ncclient(self):
        """Import the NETCONF client (ncclient) module.

        The ncclient module is not installed as part of the normal Neutron
        distributions. It is imported dynamically in this module so that
        the import can be mocked, allowing unit testing without requiring
        the installation of ncclient.

        """
        return importutils.import_module('ncclient.manager')

    def _edit_config(self, nexus_host, target='running', config='',
                     allowed_exc_strs=None):
        """Modify switch config for a target config type.

        :param nexus_host: IP address of switch to configure
        :param target: Target config type
        :param config: Configuration string in XML format
        :param allowed_exc_strs: Exceptions which have any of these strings
                                 as a subset of their exception message
                                 (str(exception)) can be ignored

        :returns None: if config was edited successfully
                 Exception object: if _edit_config() encountered an exception
                                   containing one of allowed_exc_strs

        :raises: NexusConfigFailed: if _edit_config() encountered an exception
                                    not containing one of allowed_exc_strs

        """
        if not allowed_exc_strs:
            allowed_exc_strs = []
        mgr = self.nxos_connect(nexus_host)
        try:
            LOG.debug("NexusDriver config: %s", config)
            mgr.edit_config(target=target, config=config)
        except Exception as e:
            for exc_str in allowed_exc_strs:
                if exc_str in str(e):
                    return e
                # Raise a Neutron exception. Include a description of
                # the original ncclient exception.
            raise cexc.NexusConfigFailed(config=config, exc=e)

    def nxos_connect(self, nexus_host):
        """Make SSH connection to the Nexus Switch."""
        if getattr(self.connections.get(nexus_host), 'connected', None):
            return self.connections[nexus_host]

        if not self.ncclient:
            self.ncclient = self._import_ncclient()
        nexus_ssh_port = int(self.nexus_switches[nexus_host, 'ssh_port'])
        nexus_user = self.nexus_switches[nexus_host, const.USERNAME]
        nexus_password = self.nexus_switches[nexus_host, const.PASSWORD]
        try:
            try:
                # With new ncclient version, we can pass device_params...
                man = self.ncclient.connect(host=nexus_host,
                                            port=nexus_ssh_port,
                                            username=nexus_user,
                                            password=nexus_password,
                                            device_params={"name": "nexus"})
            except TypeError:
                # ... but if that causes an error, we appear to have the old
                # ncclient installed, which doesn't understand this parameter.
                man = self.ncclient.connect(host=nexus_host,
                                            port=nexus_ssh_port,
                                            username=nexus_user,
                                            password=nexus_password)
        except Exception as e:
            # Raise a Neutron exception. Include a description of
            # the original ncclient exception.
            raise cexc.NexusConnectFailed(nexus_host=nexus_host, exc=e)

        self.connections[nexus_host] = man
        return self.connections[nexus_host]

    def create_xml_snippet(self, customized_config):
        """Create XML snippet.

        Creates the Proper XML structure for the Nexus Switch Configuration.
        """
        conf_xml_snippet = snipp.EXEC_CONF_SNIPPET % (customized_config)
        return conf_xml_snippet

    def create_vlan(self, nexus_host, vlanid, vlanname):
        """Create a VLAN on Nexus Switch given the VLAN ID and Name."""
        confstr = self.create_xml_snippet(
            snipp.CMD_VLAN_CONF_SNIPPET % (vlanid, vlanname))
        self._edit_config(nexus_host, target='running', config=confstr)

        # Enable VLAN active and no-shutdown states. Some versions of
        # Nexus switch do not allow state changes for the extended VLAN
        # range (1006-4094), but these errors can be ignored (default
        # values are appropriate).
        for snippet in [snipp.CMD_VLAN_ACTIVE_SNIPPET,
                        snipp.CMD_VLAN_NO_SHUTDOWN_SNIPPET]:
            try:
                confstr = self.create_xml_snippet(snippet % vlanid)
                self._edit_config(
                    nexus_host,
                    target='running',
                    config=confstr,
                    allowed_exc_strs=["Can't modify state for extended",
                                      "Command is only allowed on VLAN"])
            except cexc.NexusConfigFailed:
                with excutils.save_and_reraise_exception():
                    self.delete_vlan(nexus_host, vlanid)

    def delete_vlan(self, nexus_host, vlanid):
        """Delete a VLAN on Nexus Switch given the VLAN ID."""
        confstr = snipp.CMD_NO_VLAN_CONF_SNIPPET % vlanid
        confstr = self.create_xml_snippet(confstr)
        self._edit_config(nexus_host, target='running', config=confstr)

    def build_intf_confstr(self, snippet, intf_type, interface, vlanid):
        """Build the VLAN config string xml snippet to be used."""
        confstr = snippet % (intf_type, interface, vlanid, intf_type)
        confstr = self.create_xml_snippet(confstr)
        LOG.debug("NexusDriver: %s", confstr)
        return confstr

    def enable_vlan_on_trunk_int(self, nexus_host, vlanid, intf_type,
                                 interface):
        """Enable a VLAN on a trunk interface."""
        # Configure a new VLAN into the interface using 'ADD' keyword
        confstr = self.build_intf_confstr(
            snippet=snipp.CMD_INT_VLAN_ADD_SNIPPET,
            intf_type=intf_type,
            interface=interface,
            vlanid=vlanid
        )
        exc_str = ["switchport trunk allowed vlan list is empty"]
        ret_exc = self._edit_config(nexus_host, target='running',
                                    config=confstr,
                                    allowed_exc_strs=exc_str)
        if ret_exc:
            # If no switchports have been configured on the switch
            # before the new 'ADD', configure the VLAN into the
            # interface without the keyword so as to create a vlan list
            confstr = self.build_intf_confstr(
                snippet=snipp.CMD_INT_VLAN_SNIPPET,
                intf_type=intf_type,
                interface=interface,
                vlanid=vlanid
            )
            self._edit_config(nexus_host, target='running',
                              config=confstr)

    def disable_vlan_on_trunk_int(self, nexus_host, vlanid, intf_type,
                                  interface):
        """Disable a VLAN on a trunk interface."""
        confstr = (snipp.CMD_NO_VLAN_INT_SNIPPET %
                   (intf_type, interface, vlanid, intf_type))
        confstr = self.create_xml_snippet(confstr)
        self._edit_config(nexus_host, target='running', config=confstr)

    def create_and_trunk_vlan(self, nexus_host, vlan_id, vlan_name,
                              intf_type, nexus_port):
        """Create VLAN and trunk it on the specified ports."""
        self.create_vlan(nexus_host, vlan_id, vlan_name)
        LOG.debug("NexusDriver created VLAN: %s", vlan_id)
        if nexus_port:
            self.enable_vlan_on_trunk_int(nexus_host, vlan_id, intf_type,
                                          nexus_port)
