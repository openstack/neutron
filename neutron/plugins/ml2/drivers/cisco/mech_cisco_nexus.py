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
from neutron.openstack.common import excutils
from neutron.openstack.common import log as logging
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers.cisco import config as conf
from neutron.plugins.ml2.drivers.cisco import credentials_v2 as cred
from neutron.plugins.ml2.drivers.cisco import exceptions as excep
from neutron.plugins.ml2.drivers.cisco import nexus_db_v2 as nxos_db
from neutron.plugins.ml2.drivers.cisco import nexus_network_driver

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

        # Initialize credential store after database initialization
        cred.Store.initialize()

    def _valid_network_segment(self, segment):
        return (cfg.CONF.ml2_cisco.managed_physical_network is None or
                cfg.CONF.ml2_cisco.managed_physical_network ==
                segment[api.PHYSICAL_NETWORK])

    def _get_vlanid(self, context):
        segment = context.bound_segment
        if (segment and segment[api.NETWORK_TYPE] == 'vlan' and
            self._valid_network_segment(segment)):
            return context.bound_segment.get(api.SEGMENTATION_ID)

    def _is_deviceowner_compute(self, port):
        return port['device_owner'].startswith('compute')

    def _is_status_active(self, port):
        return port['status'] == n_const.PORT_STATUS_ACTIVE

    def _get_credential(self, nexus_ip):
        """Return credential information for a given Nexus IP address.

        If credential doesn't exist then also add to local dictionary.
        """
        if nexus_ip not in self.credentials:
            _nexus_username = cred.Store.get_username(nexus_ip)
            _nexus_password = cred.Store.get_password(nexus_ip)
            self.credentials[nexus_ip] = {
                'username': _nexus_username,
                'password': _nexus_password
            }
        return self.credentials[nexus_ip]

    def _manage_port(self, vlan_name, vlan_id, host, instance):
        """Called during create and update port events.

        Create a VLAN in the appropriate switch/port and configure the
        appropriate interfaces for this VLAN.
        """

        # Grab the switch IP and port for this host
        for switch_ip, attr in self._nexus_switches:
            if str(attr) == str(host):
                port_id = self._nexus_switches[switch_ip, attr]
                break
        else:
            raise excep.NexusComputeHostNotConfigured(host=host)

        # Check if this network is already in the DB
        vlan_created = False
        vlan_trunked = False

        try:
            nxos_db.get_port_vlan_switch_binding(port_id, vlan_id, switch_ip)
        except excep.NexusPortBindingNotFound:
            # Check for vlan/switch binding
            try:
                nxos_db.get_nexusvlan_binding(vlan_id, switch_ip)
            except excep.NexusPortBindingNotFound:
                # Create vlan and trunk vlan on the port
                LOG.debug(_("Nexus: create & trunk vlan %s"), vlan_name)
                self.driver.create_and_trunk_vlan(switch_ip, vlan_id,
                                                  vlan_name, port_id)
                vlan_created = True
                vlan_trunked = True
            else:
                # Only trunk vlan on the port
                LOG.debug(_("Nexus: trunk vlan %s"), vlan_name)
                self.driver.enable_vlan_on_trunk_int(switch_ip, vlan_id,
                                                     port_id)
                vlan_trunked = True

        try:
            nxos_db.add_nexusport_binding(port_id, str(vlan_id),
                                          switch_ip, instance)
        except Exception:
            with excutils.save_and_reraise_exception():
                # Add binding failed, roll back any vlan creation/enabling
                if vlan_created and vlan_trunked:
                    LOG.debug(_("Nexus: delete & untrunk vlan %s"), vlan_name)
                    self.driver.delete_and_untrunk_vlan(switch_ip, vlan_id,
                                                        port_id)
                elif vlan_created:
                    LOG.debug(_("Nexus: delete vlan %s"), vlan_name)
                    self.driver.delete_vlan(switch_ip, vlan_id)
                elif vlan_trunked:
                    LOG.debug(_("Nexus: untrunk vlan %s"), vlan_name)
                    self.driver.disable_vlan_on_trunk_int(switch_ip, vlan_id,
                                                          port_id)

    def _invoke_nexus_on_port_event(self, context):
        vlan_id = self._get_vlanid(context)
        host_id = context.current.get(portbindings.HOST_ID)

        if vlan_id and host_id:
            vlan_name = cfg.CONF.ml2_cisco.vlan_name_prefix + str(vlan_id)
            instance_id = context.current.get('device_id')
            self._manage_port(vlan_name, vlan_id, host_id, instance_id)
        else:
            LOG.debug(_("Vlan ID %(vlan_id)s or Host ID %(host_id)s missing."),
                      {'vlan_id': vlan_id, 'host_id': host_id})

    def update_port_postcommit(self, context):
        """Update port post-database commit event."""
        port = context.current

        if self._is_deviceowner_compute(port) and self._is_status_active(port):
            self._invoke_nexus_on_port_event(context)

    def delete_port_precommit(self, context):
        """Delete port pre-database commit event.

        Delete port bindings from the database and scan whether the network
        is still required on the interfaces trunked.
        """

        if not self._is_deviceowner_compute(context.current):
            return

        port = context.current
        device_id = port['device_id']
        vlan_id = self._get_vlanid(context)

        if not vlan_id or not device_id:
            return

        # Delete DB row for this port
        try:
            row = nxos_db.get_nexusvm_binding(vlan_id, device_id)
        except excep.NexusPortBindingNotFound:
            return

        switch_ip = row.switch_ip
        nexus_port = None
        if row.port_id != 'router':
            nexus_port = row.port_id

        nxos_db.remove_nexusport_binding(row.port_id, row.vlan_id,
                                         row.switch_ip, row.instance_id)

        # Check for any other bindings with the same vlan_id and switch_ip
        try:
            nxos_db.get_nexusvlan_binding(row.vlan_id, row.switch_ip)
        except excep.NexusPortBindingNotFound:
            try:
                # Delete this vlan from this switch
                if nexus_port:
                    self.driver.disable_vlan_on_trunk_int(switch_ip,
                                                          row.vlan_id,
                                                          nexus_port)
                self.driver.delete_vlan(switch_ip, row.vlan_id)
            except Exception:
                # The delete vlan operation on the Nexus failed,
                # so this delete_port request has failed. For
                # consistency, roll back the Nexus database to what
                # it was before this request.
                with excutils.save_and_reraise_exception():
                    nxos_db.add_nexusport_binding(row.port_id,
                                                  row.vlan_id,
                                                  row.switch_ip,
                                                  row.instance_id)
