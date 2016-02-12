# Copyright 2016 Huawei Technologies India Pvt. Ltd.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_db import exception as db_exc
from oslo_log import log as logging
from sqlalchemy.orm import exc
from sqlalchemy import sql

from neutron.db import agents_db
from neutron.db import bgp_db
from neutron.db import bgp_dragentscheduler_db as bgp_dras_db
from neutron._i18n import _LI, _LW
from neutron.scheduler import base_resource_filter
from neutron.scheduler import base_scheduler
from neutron.services.bgp.common import constants as bgp_consts

LOG = logging.getLogger(__name__)
BGP_SPEAKER_PER_DRAGENT = 1


class BgpDrAgentFilter(base_resource_filter.BaseResourceFilter):

    def bind(self, context, agents, bgp_speaker_id):
        """Bind the BgpSpeaker to a BgpDrAgent."""
        bound_agents = agents[:]
        for agent in agents:
            # saving agent_id to use it after rollback to avoid
            # DetachedInstanceError
            agent_id = agent.id
            binding = bgp_dras_db.BgpSpeakerDrAgentBinding()
            binding.agent_id = agent_id
            binding.bgp_speaker_id = bgp_speaker_id
            try:
                with context.session.begin(subtransactions=True):
                    context.session.add(binding)
            except db_exc.DBDuplicateEntry:
                # it's totally ok, someone just did our job!
                bound_agents.remove(agent)
                LOG.info(_LI('BgpDrAgent %s already present'), agent_id)
            LOG.debug('BgpSpeaker %(bgp_speaker_id)s is scheduled to be '
                      'hosted by BgpDrAgent %(agent_id)s',
                      {'bgp_speaker_id': bgp_speaker_id,
                       'agent_id': agent_id})
        super(BgpDrAgentFilter, self).bind(context, bound_agents,
                                           bgp_speaker_id)

    def filter_agents(self, plugin, context, bgp_speaker):
        """Return the agents that can host the BgpSpeaker."""
        agents_dict = self._get_bgp_speaker_hostable_dragents(
            plugin, context, bgp_speaker)
        if not agents_dict['hostable_agents'] or agents_dict['n_agents'] <= 0:
            return {'n_agents': 0,
                    'hostable_agents': [],
                    'hosted_agents': []}
        return agents_dict

    def _get_active_dragents(self, plugin, context):
        """Return a list of active BgpDrAgents."""
        with context.session.begin(subtransactions=True):
            active_dragents = plugin.get_agents_db(
                context, filters={
                    'agent_type': [bgp_consts.AGENT_TYPE_BGP_ROUTING],
                    'admin_state_up': [True]})
            if not active_dragents:
                return []
        return active_dragents

    def _get_num_dragents_hosting_bgp_speaker(self, bgp_speaker_id,
                                              dragent_bindings):
        return sum(1 if dragent_binding.bgp_speaker_id == bgp_speaker_id else 0
                   for dragent_binding in dragent_bindings)

    def _get_bgp_speaker_hostable_dragents(self, plugin, context, bgp_speaker):
        """Return number of additional BgpDrAgents which will actually host
           the given BgpSpeaker and a list of BgpDrAgents which can host the
           given BgpSpeaker
        """
        # only one BgpSpeaker can be hosted by a BgpDrAgent for now.
        dragents_per_bgp_speaker = BGP_SPEAKER_PER_DRAGENT
        dragent_bindings = plugin.get_dragent_bgp_speaker_bindings(context)
        agents_hosting = [dragent_binding.agent_id
                          for dragent_binding in dragent_bindings]

        num_dragents_hosting_bgp_speaker = (
            self._get_num_dragents_hosting_bgp_speaker(bgp_speaker['id'],
                                                       dragent_bindings))
        n_agents = dragents_per_bgp_speaker - num_dragents_hosting_bgp_speaker
        if n_agents <= 0:
            return {'n_agents': 0,
                    'hostable_agents': [],
                    'hosted_agents': []}

        active_dragents = self._get_active_dragents(plugin, context)
        hostable_dragents = [
            agent for agent in set(active_dragents)
            if agent.id not in agents_hosting and plugin.is_eligible_agent(
                active=True, agent=agent)
        ]
        if not hostable_dragents:
            return {'n_agents': 0,
                    'hostable_agents': [],
                    'hosted_agents': []}

        n_agents = min(len(hostable_dragents), n_agents)
        return {'n_agents': n_agents,
                'hostable_agents': hostable_dragents,
                'hosted_agents': num_dragents_hosting_bgp_speaker}


class BgpDrAgentSchedulerBase(BgpDrAgentFilter):

    def schedule_unscheduled_bgp_speakers(self, context, host):
        """Schedule unscheduled BgpSpeaker to a BgpDrAgent.
        """

        LOG.debug('Started auto-scheduling on host %s', host)
        with context.session.begin(subtransactions=True):
            query = context.session.query(agents_db.Agent)
            query = query.filter_by(
                agent_type=bgp_consts.AGENT_TYPE_BGP_ROUTING,
                host=host,
                admin_state_up=sql.true())
            try:
                bgp_dragent = query.one()
            except (exc.NoResultFound):
                LOG.debug('No enabled BgpDrAgent on host %s', host)
                return False

            if agents_db.AgentDbMixin.is_agent_down(
                    bgp_dragent.heartbeat_timestamp):
                LOG.warn(_LW('BgpDrAgent %s is down'), bgp_dragent.id)
                return False

            if self._is_bgp_speaker_hosted(context, bgp_dragent['id']):
                # One BgpDrAgent can only host one BGP speaker
                LOG.debug('BgpDrAgent already hosting a speaker on host %s. '
                          'Cannot schedule an another one', host)
                return False

            unscheduled_speakers = self._get_unscheduled_bgp_speakers(context)
            if not unscheduled_speakers:
                LOG.debug('Nothing to auto-schedule on host %s', host)
                return False

            self.bind(context, [bgp_dragent], unscheduled_speakers[0])
        return True

    def _is_bgp_speaker_hosted(self, context, agent_id):
        speaker_binding_model = bgp_dras_db.BgpSpeakerDrAgentBinding

        query = context.session.query(speaker_binding_model)
        query = query.filter(speaker_binding_model.agent_id == agent_id)

        return query.count() > 0

    def _get_unscheduled_bgp_speakers(self, context):
        """BGP speakers that needs to be scheduled.
        """

        no_agent_binding = ~sql.exists().where(
            bgp_db.BgpSpeaker.id ==
            bgp_dras_db.BgpSpeakerDrAgentBinding.bgp_speaker_id)
        query = context.session.query(bgp_db.BgpSpeaker.id).filter(
            no_agent_binding)
        return [bgp_speaker_id_[0] for bgp_speaker_id_ in query]


class ChanceScheduler(base_scheduler.BaseChanceScheduler,
                      BgpDrAgentSchedulerBase):

    def __init__(self):
        super(ChanceScheduler, self).__init__(self)


class WeightScheduler(base_scheduler.BaseWeightScheduler,
                      BgpDrAgentSchedulerBase):

    def __init__(self):
        super(WeightScheduler, self).__init__(self)
