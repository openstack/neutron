# Copyright 2021 Red Hat, Inc.
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

import itertools

from keystoneauth1 import exceptions as ks_exc
from neutron_lib import constants as n_const
from neutron_lib.placement import constants as placement_constants
from neutron_lib.placement import utils as placement_utils
from neutron_lib.plugins import constants as plugins_constants
from neutron_lib.plugins import directory
from neutron_lib.utils import helpers
from oslo_log import log as logging
from ovsdbapp.backend.ovs_idl import event as row_event

from neutron.agent.common import placement_report
from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils as ovn_utils
from neutron.common import utils as common_utils


LOG = logging.getLogger(__name__)


def _parse_ovn_cms_options(chassis):
    cms_options = ovn_utils.get_ovn_cms_options(chassis)
    return {n_const.RP_BANDWIDTHS: _parse_bandwidths(cms_options),
            n_const.RP_INVENTORY_DEFAULTS: _parse_inventory_defaults(
                cms_options),
            ovn_const.RP_HYPERVISORS: _parse_hypervisors(cms_options)}


def _parse_bridge_mappings(chassis):
    other_config = ovn_utils.get_ovn_chassis_other_config(chassis)
    bridge_mappings = other_config.get('ovn-bridge-mappings', '')
    bridge_mappings = helpers.parse_mappings(bridge_mappings.split(','))
    return {k: [v] for k, v in bridge_mappings.items()}


def _parse_placement_option(option_name, cms_options):
    for cms_option in (cms_option for cms_option in cms_options if
                       option_name in cms_option):
        try:
            return cms_option.split('=')[1]
        except IndexError:
            break


def _parse_bandwidths(cms_options):
    bw_values = _parse_placement_option(n_const.RP_BANDWIDTHS, cms_options)
    if not bw_values:
        return {}

    return placement_utils.parse_rp_bandwidths(bw_values.split(';'))


def _parse_inventory_defaults(cms_options):
    inv_defaults = _parse_placement_option(n_const.RP_INVENTORY_DEFAULTS,
                                           cms_options)
    if not inv_defaults:
        return {}

    inventory = {}
    for inv_default in inv_defaults.split(';'):
        for key in placement_constants.INVENTORY_OPTIONS:
            if key in inv_default:
                inventory[key] = inv_default.split(':')[1]
    return placement_utils.parse_rp_inventory_defaults(inventory)


def _parse_hypervisors(cms_options):
    hyperv = _parse_placement_option(ovn_const.RP_HYPERVISORS, cms_options)
    if not hyperv:
        return {}

    return helpers.parse_mappings(hyperv.split(';'), unique_values=False)


def _send_deferred_batch(state):
    if not state:
        return

    deferred_batch = state.deferred_sync()
    for deferred in deferred_batch:
        try:
            LOG.debug('Placement client: %s', str(deferred))
            deferred.execute()
        except Exception:
            LOG.exception('Placement client call failed: %s', str(deferred))


def dict_chassis_config(state):
    if state:
        return {n_const.RP_BANDWIDTHS: state._rp_bandwidths,
                n_const.RP_INVENTORY_DEFAULTS: state._rp_inventory_defaults,
                ovn_const.RP_HYPERVISORS: state._hypervisor_rps}


class ChassisBandwidthConfigEvent(row_event.RowEvent):
    """Chassis create update event to track the bandwidth config changes."""

    def __init__(self, driver):
        self._driver = driver
        # NOTE(ralonsoh): BW resource provider information is stored in
        # "Chassis", not "Chassis_Private".
        table = 'Chassis'
        events = (self.ROW_CREATE, self.ROW_UPDATE)
        super().__init__(events, table, None)
        self.event_name = 'ChassisBandwidthConfigEvent'

    @property
    def placement_extension(self):
        if self._driver._post_fork_event.is_set():
            return self._driver._ovn_client.placement_extension

    def match_fn(self, event, row, old=None):
        # If the OVNMechanismDriver OVNClient has not been instantiated, the
        # event is skipped. All chassis configurations are read during the
        # OVN placement extension initialization.
        if (not self.placement_extension or
                not self.placement_extension.enabled):
            return False
        elif event == self.ROW_CREATE:
            return True
        elif event == self.ROW_UPDATE and old and hasattr(old, 'other_config'):
            row_bw = _parse_ovn_cms_options(row)
            old_bw = _parse_ovn_cms_options(old)
            if row_bw != old_bw:
                return True
        return False

    def run(self, event, row, old):
        name2uuid = self.placement_extension.name2uuid()
        state = self.placement_extension.build_placement_state(row, name2uuid)
        if not state:
            return

        _send_deferred_batch(state)
        ch_config = dict_chassis_config(state)
        LOG.debug('OVN chassis %(chassis)s Placement configuration modified: '
                  '%(config)s', {'chassis': row.name, 'config': ch_config})


@common_utils.SingletonDecorator
class OVNClientPlacementExtension(object):
    """OVN client Placement API extension"""

    def __init__(self, driver):
        LOG.info('Starting OVNClientPlacementExtension')
        super().__init__()
        self._config_event = None
        self._reset(driver)

    def _reset(self, driver):
        """Reset the interval members values
        This class is a singleton. Once initialized, any other new instance
        will return the same object reference with the same member values.
        This method is used to reset all of them as when the class is initially
        instantiated if needed.
        """
        self._driver = driver
        self._placement_plugin = None
        self._plugin = None
        self.uuid_ns = ovn_const.OVN_RP_UUID
        self.supported_vnic_types = ovn_const.OVN_SUPPORTED_VNIC_TYPES

    @property
    def placement_plugin(self):
        if self._placement_plugin is None:
            self._placement_plugin = directory.get_plugin(
                plugins_constants.PLACEMENT_REPORT)
        return self._placement_plugin

    @property
    def enabled(self):
        return bool(self.placement_plugin)

    @property
    def plugin(self):
        if self._plugin is None:
            self._plugin = self._driver._plugin
        return self._plugin

    @property
    def ovn_mech_driver(self):
        if self._ovn_mech_driver is None:
            self._ovn_mech_driver = (
                self.plugin.mechanism_manager.mech_drivers['ovn'].obj)
        return self._ovn_mech_driver

    def get_chassis_config(self):
        """Read all Chassis BW config and returns the Placement states"""
        chassis = {}
        name2uuid = self.name2uuid()
        for ch in self._driver._sb_idl.chassis_list().execute(
                check_error=True):
            state = self.build_placement_state(ch, name2uuid)
            if state:
                chassis[ch.name] = state

        return chassis

    def read_initial_chassis_config(self):
        """Read the Chassis BW configuration and update the Placement API

        This method is called once from the MaintenanceWorker when the Neutron
        server starts.
        """
        if not self.enabled:
            return

        chassis = self.get_chassis_config()
        for state in chassis.values():
            _send_deferred_batch(state)
        msg = ', '.join(['Chassis %s: %s' % (name, dict_chassis_config(state))
                         for (name, state) in chassis.items()]) or '(no info)'
        LOG.debug('OVN chassis Placement initial configuration: %s', msg)
        return chassis

    def name2uuid(self, name=None):
        try:
            rps = self.placement_plugin._placement_client.\
                list_resource_providers(name=name)['resource_providers']
        except (ks_exc.HttpError, ks_exc.ClientException):
            LOG.warning('Error connecting to Placement API.')
            return {}

        _name2uuid = {rp['name']: rp['uuid'] for rp in rps}
        LOG.info('Placement information about resource providers '
                 '(name:uuid):%s ', _name2uuid)
        return _name2uuid

    def build_placement_state(self, chassis, name2uuid):
        bridge_mappings = _parse_bridge_mappings(chassis)
        cms_options = _parse_ovn_cms_options(chassis)
        LOG.debug('Building placement options for chassis %s: %s',
                  chassis.name, cms_options)
        hypervisor_rps = {}
        for device, hyperv in cms_options[ovn_const.RP_HYPERVISORS].items():
            try:
                hypervisor_rps[device] = {'name': hyperv,
                                          'uuid': name2uuid[hyperv]}
            except (KeyError, AttributeError):
                continue

        bridges = set(itertools.chain(*bridge_mappings.values()))
        # Remove "cms_options[RP_BANDWIDTHS]" not present in "hypervisor_rps"
        # and "bridge_mappings". If we don't have a way to match the RP bridge
        # with a host ("hypervisor_rps") or a way to match the RP bridge with
        # an external network ("bridge_mappings"), this value is irrelevant.
        rp_bw = cms_options[n_const.RP_BANDWIDTHS]
        if rp_bw:
            cms_options[n_const.RP_BANDWIDTHS] = {
                device: bw for device, bw in rp_bw.items() if
                device in hypervisor_rps and device in bridges}

        # NOTE(ralonsoh): OVN only reports min BW RPs; packet processing RPs
        # will be added in a future implementation. If no RP_BANDWIDTHS values
        # are present (that means there is no BW information for any interface
        # in this host), no "PlacementState" is returned.
        return placement_report.PlacementState(
            rp_bandwidths=cms_options[n_const.RP_BANDWIDTHS],
            rp_inventory_defaults=cms_options[n_const.RP_INVENTORY_DEFAULTS],
            rp_pkt_processing={},
            rp_pkt_processing_inventory_defaults=None,
            driver_uuid_namespace=self.uuid_ns,
            agent_type=ovn_const.OVN_CONTROLLER_AGENT,
            hypervisor_rps=hypervisor_rps,
            device_mappings=bridge_mappings,
            supported_vnic_types=self.supported_vnic_types,
            client=self.placement_plugin._placement_client)
