# Copyright 2018 Ericsson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from keystoneauth1 import exceptions as ks_exc
from neutron_lib.agent import constants as agent_const
from neutron_lib.api.definitions import agent_resources_synced
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants as n_const
from neutron_lib.placement import client as place_client
from neutron_lib.plugins import directory
from neutron_lib.services import base as service_base
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.common import placement_report
from neutron.notifiers import batch_notifier

LOG = logging.getLogger(__name__)

PLUGIN_TYPE = "placement_report"


@registry.has_registry_receivers
class PlacementReportPlugin(service_base.ServicePluginBase):

    supported_extension_aliases = []

    # A service plugin without claiming support for filter validation would
    # disable filter validation for all other plugins, so we report support
    # although this plugin doesn't have filters.
    __filter_validation_support = True

    @classmethod
    def get_plugin_type(cls):
        return PLUGIN_TYPE

    def get_plugin_description(self):
        return "Sync placement info from agent to server to placement."

    def __init__(self):
        self._core_plugin = directory.get_plugin()
        # NOTE(bence romsics): The following bug and fix may be relevant here.
        # https://bugs.launchpad.net/nova/+bug/1697825
        # https://review.opendev.org/493536
        self._placement_client = place_client.PlacementAPIClient(cfg.CONF)
        self._agents = PlacementReporterAgents(self._core_plugin)
        self._batch_notifier = batch_notifier.BatchNotifier(
            cfg.CONF.send_events_interval, self._execute_deferred)

    def _execute_deferred(self, deferred_batch):
        for deferred in deferred_batch:
            deferred()

    def _get_rp_by_name(self, name):
        rps = self._placement_client.list_resource_providers(
            name=name)['resource_providers']
        # RP names are unique, therefore we can get 0 or 1. But not many.
        return rps[0]

    def _sync_placement_state(self, agent, agent_db):
        configurations = agent['configurations']
        mech_driver = self._agents.mechanism_driver_by_agent_type(
            agent['agent_type'])
        uuid_ns = mech_driver.resource_provider_uuid5_namespace
        supported_vnic_types = mech_driver.supported_vnic_types
        device_mappings = mech_driver.get_standard_device_mappings(agent)
        if 'resource_provider_hypervisors' in configurations:
            # When the agent has the fix for
            # https://bugs.launchpad.net/neutron/+bug/1853840
            # it sends us hypervisor names (compute nodes in nova terminology).
            hypervisors = configurations['resource_provider_hypervisors']
        else:
            # For older agents without the fix we have to assume the old
            # buggy behavior. There we assumed DEFAULT.host is the same as the
            # hypervisor name, which is true in many deployments, but not
            # always. (In nova terminology: The compute host's DEFAULT.host is
            # not necessarily the same as the compute node name. We may even
            # have multiple compute nodes behind a compute host.)
            # TODO(bence romsics): This else branch can be removed when we no
            # longer want to support pre-Ussuri agents.
            hypervisors = {
                device: agent['host']
                for device
                in configurations['resource_provider_bandwidths'].keys()
            }

        log_msg = (
            'Synchronization of resources '
            'of agent type %(type)s '
            'at host %(host)s '
            'to placement %(result)s.')

        try:
            name2uuid = {}
            for name in hypervisors.values():
                name2uuid[name] = self._get_rp_by_name(name=name)['uuid']

            hypervisor_rps = {}
            for device, hypervisor in hypervisors.items():
                hypervisor_rps[device] = {
                    'name': hypervisor,
                    'uuid': name2uuid[hypervisor],
                }
        except (IndexError, ks_exc.HttpError, ks_exc.ClientException):
            agent_db.resources_synced = False
            agent_db.update()

            LOG.warning(
                log_msg,
                {'type': agent['agent_type'],
                 'host': agent['host'],
                 'result': 'failed'})

            return

        state = placement_report.PlacementState(
            rp_bandwidths=configurations[
                'resource_provider_bandwidths'],
            rp_inventory_defaults=configurations[
                'resource_provider_inventory_defaults'],
            # RP_PP_WITHOUT_DIRECTION and RP_PP_WITH_DIRECTION are mutually
            # exclusive options. Use the one that was provided or fallback to
            # an empty dict.
            rp_pkt_processing=(
                configurations[n_const.RP_PP_WITHOUT_DIRECTION]
                if configurations.get(
                    n_const.RP_PP_WITHOUT_DIRECTION)
                else configurations.get(
                    n_const.RP_PP_WITH_DIRECTION, {})),
            rp_pkt_processing_inventory_defaults=configurations.get(
                n_const.RP_PP_INVENTORY_DEFAULTS, {}),
            driver_uuid_namespace=uuid_ns,
            agent_type=agent['agent_type'],
            hypervisor_rps=hypervisor_rps,
            device_mappings=device_mappings,
            supported_vnic_types=supported_vnic_types,
            client=self._placement_client)

        deferred_batch = state.deferred_sync()

        # NOTE(bence romsics): Some client calls depend on earlier
        # ones, but not all. There are calls in a batch that can succeed
        # independently of earlier calls. Therefore even if a call fails
        # we have to suppress its failure so the later independent calls
        # have a chance to succeed.  If we queue up the deferred client
        # calls one by one then we cannot handle errors at the end of
        # a batch. So instead we should wrap the deferred client calls
        # in a single deferred batch which executes the client calls,
        # continuing to the next client call even if there was an error
        # but remembering if an error happened. Then at the end of the
        # batch (also having access to the agent object) set the agent's
        # resources_synced attribute according to the success/failure
        # of the batch. Since each client call does monkey patched I/O
        # we'll yield to other eventlet threads in each call therefore
        # the performance should not be affected by the wrapping.
        def batch():
            errors = False

            for deferred in deferred_batch:
                try:
                    LOG.debug('placement client: %s', deferred)
                    deferred.execute()
                except Exception as e:
                    errors = True
                    placement_error_str = \
                        're-parenting a provider is not currently allowed'
                    if (placement_error_str in str(e)):
                        msg = (
                            'placement client call failed'
                            ' (this may be due to bug'
                            ' https://launchpad.net/bugs/1921150): %s'
                        )
                    else:
                        msg = 'placement client call failed: %s'
                    LOG.exception(msg, str(deferred))

            resources_synced = not errors
            agent_db.resources_synced = resources_synced
            agent_db.update()

            if resources_synced:
                LOG.debug(
                    log_msg,
                    {'type': agent['agent_type'],
                     'host': agent['host'],
                     'result': 'succeeded'})
            else:
                LOG.warning(
                    log_msg,
                    {'type': agent['agent_type'],
                     'host': agent['host'],
                     'result': 'failed'})

        self._batch_notifier.queue_event(batch)

    @registry.receives(resources.AGENT,
                       [events.AFTER_CREATE, events.AFTER_UPDATE])
    def handle_placement_config(self, resource, event, trigger, payload):
        # NOTE(bence romsics): This method gets called a lot, keep it quick.
        agent = payload.desired_state
        status = payload.metadata.get('status')
        context = payload.context
        if agent['agent_type'] not in self._agents.supported_agent_types:
            return
        if 'resource_provider_bandwidths' not in agent['configurations']:
            LOG.warning(
                "The mechanism driver claims agent type supports "
                "placement reports, but the agent does not report "
                "'resource_provider_bandwidths' in its configurations. "
                "host: %(host)s, type: %(type)s",
                {'host': agent['agent_type'],
                 'type': agent['host']})
            return

        # We need to get the same agent as in
        # neutron.db.agents_db.AgentDbMixin.create_or_update_agent()
        agent_db = self._core_plugin._get_agent_by_type_and_host(
            context, agent['agent_type'], agent['host'])

        # sync the state known by us to placement
        if (
                # agent object in API (re-)created
                status == agent_const.AGENT_NEW or
                # agent (re-)started (even without config change)
                'start_flag' in agent or
                # never tried to sync yet or last sync failed
                not agent_db[agent_resources_synced.RESOURCES_SYNCED]):
            LOG.debug(
                'placement: syncing state for agent type %s on host %s',
                agent['agent_type'], agent['host'])
            self._sync_placement_state(agent, agent_db)
        else:
            LOG.debug(
                'placement: nothing to sync for agent type %s on host %s',
                agent['agent_type'], agent['host'])


class PlacementReporterAgents:

    # Yep, this is meant to depend on ML2.
    def __init__(self, ml2_plugin):
        try:
            self._mechanism_drivers = ml2_plugin.mechanism_manager.\
                ordered_mech_drivers
        except AttributeError:
            LOG.error(
                "Invalid plugin configuration: "
                "The placement service plugin depends on the ML2 core plugin. "
                "You likely want to remove 'placement' from "
                "neutron.conf: DEFAULT.service_plugins")
            raise
        self._supported_agent_types = None
        self._agent_type_to_mech_driver = {}

    @property
    def supported_agent_types(self):
        if self._supported_agent_types is None:
            # NOTE(bence romsics): We treat the presence of the
            # RP uuid namespace a proxy for supporting placement reports from
            # the driver's agent type. But we could introduce a property/logic
            # explicitly describing the agent types supporting placement
            # reports any time if this proved to be insufficient.
            self._supported_agent_types = [
                driver.obj.agent_type
                for driver in self._mechanism_drivers
                if (driver.obj.resource_provider_uuid5_namespace is
                    not None and hasattr(driver.obj, 'agent_type') and
                    driver.obj.agent_type)]
            supported_agents = ', '.join(self._supported_agent_types) or 'None'
            LOG.debug('agent types supporting placement reports: %s',
                      supported_agents)
        return self._supported_agent_types

    def mechanism_driver_by_agent_type(self, agent_type):
        if agent_type not in self._agent_type_to_mech_driver:
            for driver in self._mechanism_drivers:
                if (hasattr(driver.obj, 'agent_type') and
                        agent_type == driver.obj.agent_type):
                    self._agent_type_to_mech_driver[agent_type] = driver.obj
                    break
        return self._agent_type_to_mech_driver[agent_type]
