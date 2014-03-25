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
ML2 Mechanism Driver for Cisco Nexus platforms.
"""

from oslo.config import cfg

from neutron.common import constants as n_const
from neutron.extensions import portbindings
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants as p_const
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.cisco.nexus import config as conf
from neutron.plugins.ml2.drivers.cisco.nexus import credentials_v2 as cred
from neutron.plugins.ml2.drivers.cisco.nexus import exceptions as excep
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_db_v2 as nxos_db
from neutron.plugins.ml2.drivers.cisco.nexus import nexus_network_driver

LOG = logging.getLogger(__name__)


class CiscoNexusMechanismDriver(api.MechanismDriver):

    """Cisco Nexus ML2 Mechanism Driver."""

    def initialize(self):
        # Create ML2 device dictionary from ml2_conf.ini entries.
        conf.ML2MechCiscoConfig()

        # Extract configuration parameters from the configuration file.
        self._nexus_switches = conf.ML2MechCiscoConfig.nexus_dict
        LOG.debug(_("nexus_switches found = %s"), self._nexus_switches)

        self.credentials = {}
        self.driver = nexus_network_driver.CiscoNexusDriver()

        # Initialize credential store after database initialization.
        cred.Store.initialize()

    def _valid_network_segment(self, segment):
        return (cfg.CONF.ml2_cisco.managed_physical_network is None or
                cfg.CONF.ml2_cisco.managed_physical_network ==
                segment[api.PHYSICAL_NETWORK])

    def _get_vlanid(self, segment):
        if (segment and segment[api.NETWORK_TYPE] == p_const.TYPE_VLAN and
            self._valid_network_segment(segment)):
            return segment.get(api.SEGMENTATION_ID)

    def _is_deviceowner_compute(self, port):
        return port['device_owner'].startswith('compute')

    def _is_status_active(self, port):
        return port['status'] == n_const.PORT_STATUS_ACTIVE

    def _get_switch_info(self, host_id):
        for switch_ip, attr in self._nexus_switches:
            if str(attr) == str(host_id):
                port_id = self._nexus_switches[switch_ip, attr]
                return port_id, switch_ip
        else:
            raise excep.NexusComputeHostNotConfigured(host=host_id)

    def _configure_nxos_db(self, vlan_id, device_id, host_id):
        """Create the nexus database entry.

        Called during update precommit port event.
        """
        port_id, switch_ip = self._get_switch_info(host_id)
        nxos_db.add_nexusport_binding(port_id, str(vlan_id), switch_ip,
                                      device_id)

    def _configure_switch_entry(self, vlan_id, device_id, host_id):
        """Create a nexus switch entry.

        if needed, create a VLAN in the appropriate switch/port and
        configure the appropriate interfaces for this VLAN.

        Called during update postcommit port event.
        """
        port_id, switch_ip = self._get_switch_info(host_id)
        vlan_name = cfg.CONF.ml2_cisco.vlan_name_prefix + str(vlan_id)

        # Check to see if this is the first binding to use this vlan on the
        # switch/port. Configure switch accordingly.
        bindings = nxos_db.get_nexusvlan_binding(vlan_id, switch_ip)
        if len(bindings) == 1:
            LOG.debug(_("Nexus: create & trunk vlan %s"), vlan_name)
            self.driver.create_and_trunk_vlan(switch_ip, vlan_id, vlan_name,
                                              port_id)
        else:
            LOG.debug(_("Nexus: trunk vlan %s"), vlan_name)
            self.driver.enable_vlan_on_trunk_int(switch_ip, vlan_id, port_id)

    def _delete_nxos_db(self, vlan_id, device_id, host_id):
        """Delete the nexus database entry.

        Called during delete precommit port event.
        """
        try:
            row = nxos_db.get_nexusvm_binding(vlan_id, device_id)
            nxos_db.remove_nexusport_binding(row.port_id, row.vlan_id,
                                             row.switch_ip, row.instance_id)
        except excep.NexusPortBindingNotFound:
            return

    def _delete_switch_entry(self, vlan_id, device_id, host_id):
        """Delete the nexus switch entry.

        By accessing the current db entries determine if switch
        configuration can be removed.

        Called during update postcommit port event.
        """
        port_id, switch_ip = self._get_switch_info(host_id)

        # if there are no remaining db entries using this vlan on this nexus
        # switch port then remove vlan from the switchport trunk.
        try:
            nxos_db.get_port_vlan_switch_binding(port_id, vlan_id, switch_ip)
        except excep.NexusPortBindingNotFound:
            self.driver.disable_vlan_on_trunk_int(switch_ip, vlan_id, port_id)

            # if there are no remaining db entries using this vlan on this
            # nexus switch then remove the vlan.
            try:
                nxos_db.get_nexusvlan_binding(vlan_id, switch_ip)
            except excep.NexusPortBindingNotFound:
                self.driver.delete_vlan(switch_ip, vlan_id)

    def _is_vm_migration(self, context):
        if not context.bound_segment and context.original_bound_segment:
            return (context.current.get(portbindings.HOST_ID) !=
                    context.original.get(portbindings.HOST_ID))

    def _port_action(self, port, segment, func):
        """Verify configuration and then process event."""
        device_id = port.get('device_id')
        host_id = port.get(portbindings.HOST_ID)
        vlan_id = self._get_vlanid(segment)

        if vlan_id and device_id and host_id:
            func(vlan_id, device_id, host_id)
        else:
            fields = "vlan_id " if not vlan_id else ""
            fields += "device_id " if not device_id else ""
            fields += "host_id" if not host_id else ""
            raise excep.NexusMissingRequiredFields(fields=fields)

    def update_port_precommit(self, context):
        """Update port pre-database transaction commit event."""

        # if VM migration is occurring then remove previous database entry
        # else process update event.
        if self._is_vm_migration(context):
            self._port_action(context.original,
                              context.original_bound_segment,
                              self._delete_nxos_db)
        else:
            if (self._is_deviceowner_compute(context.current) and
                self._is_status_active(context.current)):
                self._port_action(context.current,
                                  context.bound_segment,
                                  self._configure_nxos_db)

    def update_port_postcommit(self, context):
        """Update port non-database commit event."""

        # if VM migration is occurring then remove previous nexus switch entry
        # else process update event.
        if self._is_vm_migration(context):
            self._port_action(context.original,
                              context.original_bound_segment,
                              self._delete_switch_entry)
        else:
            if (self._is_deviceowner_compute(context.current) and
                self._is_status_active(context.current)):
                self._port_action(context.current,
                                  context.bound_segment,
                                  self._configure_switch_entry)

    def delete_port_precommit(self, context):
        """Delete port pre-database commit event."""
        if self._is_deviceowner_compute(context.current):
            self._port_action(context.current,
                              context.bound_segment,
                              self._delete_nxos_db)

    def delete_port_postcommit(self, context):
        """Delete port non-database commit event."""
        if self._is_deviceowner_compute(context.current):
            self._port_action(context.current,
                              context.bound_segment,
                              self._delete_switch_entry)
