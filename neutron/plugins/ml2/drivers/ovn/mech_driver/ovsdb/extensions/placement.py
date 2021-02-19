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

from keystoneauth1 import exceptions as ks_exc
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
    return {ovn_const.RP_BANDWIDTHS: _parse_bandwidths(cms_options),
            ovn_const.RP_INVENTORY_DEFAULTS: _parse_inventory_defaults(
                cms_options),
            ovn_const.RP_HYPERVISORS: _parse_hypervisors(cms_options)}


def _parse_bridge_mappings(chassis):
    bridge_mappings = chassis.external_ids.get('ovn-bridge-mappings', '')
    bridge_mappings = helpers.parse_mappings(bridge_mappings.split(','),
                                             unique_values=False)
    return {k: [v] for k, v in bridge_mappings.items()}


def _parse_bandwidths(cms_options):
    for cms_option in cms_options:
        if ovn_const.RP_BANDWIDTHS in cms_option:
            bw_values = cms_option.split('=')[1]
            break
    else:
        return

    if bw_values:
        return placement_utils.parse_rp_bandwidths(bw_values.split(';'))


def _parse_inventory_defaults(cms_options):
    for cms_option in cms_options:
        if ovn_const.RP_INVENTORY_DEFAULTS in cms_option:
            inv_defaults = cms_option.split('=')[1]
            break
    else:
        return

    if not inv_defaults:
        return

    inventory = {}
    for inv_default in inv_defaults.split(';'):
        for key in placement_constants.INVENTORY_OPTIONS:
            if key in inv_default:
                inventory[key] = inv_default.split(':')[1]
    return placement_utils.parse_rp_inventory_defaults(inventory)


def _parse_hypervisors(cms_options):
    for cms_option in cms_options:
        if ovn_const.RP_HYPERVISORS in cms_option:
            hypervisors = cms_option.split('=')[1]
            break
    else:
        return

    if hypervisors:
        return helpers.parse_mappings(hypervisors.split(';'),
                                      unique_values=False)


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


def _dict_chassis_config(state):
    if state:
        return {ovn_const.RP_BANDWIDTHS: state._rp_bandwidths,
                ovn_const.RP_INVENTORY_DEFAULTS: state._rp_inventory_defaults,
                ovn_const.RP_HYPERVISORS: state._hypervisor_rps}


class ChassisBandwidthConfigEvent(row_event.RowEvent):
    """Chassis create update event to track the bandwidth config changes."""

    def __init__(self, placement_extension):
        self._placement_extension = placement_extension
        # NOTE(ralonsoh): BW resource provider information is stored in
        # "Chassis", not "Chassis_Private".
        table = 'Chassis'
        events = (self.ROW_CREATE, self.ROW_UPDATE)
        super().__init__(events, table, None)
        self.event_name = 'ChassisBandwidthConfigEvent'

    def run(self, event, row, old):
        name2uuid = self._placement_extension.name2uuid()
        state = self._placement_extension.build_placement_state(row, name2uuid)
        _send_deferred_batch(state)
        self._placement_extension.add_chassis_config(
            row.name, _dict_chassis_config(state))
        ch_config = self._placement_extension.get_chassis_config(row.name)
        LOG.debug('OVN chassis %(chassis)s Placement configuration modified: '
                  '%(config)s', {'chassis': row.name, 'config': ch_config})


@common_utils.SingletonDecorator
class OVNClientPlacementExtension(object):
    """OVN client Placement API extension"""

    def __init__(self, driver):
        LOG.info('Starting OVNClientPlacementExtension')
        super().__init__()
        self._driver = driver
        self._placement_plugin = None
        self._plugin = None
        self._ovn_mech_driver = None
        self._enabled = bool(self.placement_plugin)
        self._chassis = {}  # Initial config read could take some time.
        if not self._enabled:
            return

        try:
            self._driver._sb_idl.idl.notify_handler.watch_events(
                [ChassisBandwidthConfigEvent(self)])
        except AttributeError:
            self._enabled = False

        if not self._enabled:
            return

        self.uuid_ns = self.ovn_mech_driver.resource_provider_uuid5_namespace
        self.supported_vnic_types = self.ovn_mech_driver.supported_vnic_types
        self._chassis = self._read_initial_chassis_config()

    @property
    def placement_plugin(self):
        if self._placement_plugin is None:
            self._placement_plugin = directory.get_plugin(
                plugins_constants.PLACEMENT_REPORT)
        return self._placement_plugin

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

    @property
    def chassis(self):
        return self._chassis

    def _read_initial_chassis_config(self):
        chassis = {}
        name2uuid = self.name2uuid()
        for ch in self._driver._sb_idl.chassis_list().execute(
                check_error=True):
            state = self.build_placement_state(ch, name2uuid)
            _send_deferred_batch(state)
            config = _dict_chassis_config(state)
            if config:
                chassis[ch.name] = config

        msg = '\n'.join(['Chassis %s: %s' % (name, config)
                         for (name, config) in chassis.items()])
        LOG.debug('OVN chassis Placement initial configuration:\n%s', msg)
        return chassis

    def name2uuid(self, name=None):
        try:
            rps = self.placement_plugin._placement_client.\
                list_resource_providers(name=name)['resource_providers']
        except (ks_exc.HttpError, ks_exc.ClientException):
            LOG.warning('Error connecting to Placement API.')
            return {}

        return {rp['name']: rp['uuid'] for rp in rps}

    def build_placement_state(self, chassis, name2uuid):
        bridge_mappings = _parse_bridge_mappings(chassis)
        cms_options = _parse_ovn_cms_options(chassis)
        LOG.debug('Building placement options for chassis %s: %s',
                  chassis.name, cms_options)
        hypervisor_rps = {}
        try:
            for device, hyperv in cms_options[
                    ovn_const.RP_HYPERVISORS].items():
                hypervisor_rps[device] = {'name': hyperv,
                                          'uuid': name2uuid[hyperv]}
        except KeyError:
            LOG.warning('Error updating BW information from chassis '
                        '%(chassis)s, CMS options: %(cms_options)s',
                        {'chassis': chassis.name, 'cms_options': cms_options})
            return

        return placement_report.PlacementState(
            rp_bandwidths=cms_options[ovn_const.RP_BANDWIDTHS],
            rp_inventory_defaults=cms_options[
                ovn_const.RP_INVENTORY_DEFAULTS],
            driver_uuid_namespace=self.uuid_ns,
            agent_type=ovn_const.OVN_CONTROLLER_AGENT,
            hypervisor_rps=hypervisor_rps,
            device_mappings=bridge_mappings,
            supported_vnic_types=self.supported_vnic_types,
            client=self.placement_plugin._placement_client)

    def get_chassis_config(self, chassis_name):
        try:
            return self._chassis[chassis_name]
        except KeyError:
            return

    def add_chassis_config(self, chassis_name, config):
        if config:
            self._chassis[chassis_name] = config
