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

from oslo_config import cfg
from oslo_db import exception as db_exc
from oslo_log import log as logging
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron._i18n import _
from neutron._i18n import _LW
from neutron.db import agents_db
from neutron.db import agentschedulers_db as as_db
from neutron.db import model_base
from neutron.extensions import bgp_dragentscheduler as bgp_dras_ext
from neutron.services.bgp.common import constants as bgp_consts


LOG = logging.getLogger(__name__)


BGP_DRAGENT_SCHEDULER_OPTS = [
    cfg.StrOpt(
        'bgp_drscheduler_driver',
        default='neutron.services.bgp.scheduler'
                '.bgp_dragent_scheduler.ChanceScheduler',
        help=_('Driver used for scheduling BGP speakers to BGP DrAgent'))
]

cfg.CONF.register_opts(BGP_DRAGENT_SCHEDULER_OPTS)


class BgpSpeakerDrAgentBinding(model_base.BASEV2):
    """Represents a mapping between BGP speaker and BGP DRAgent"""

    __tablename__ = 'bgp_speaker_dragent_bindings'

    bgp_speaker_id = sa.Column(sa.String(length=36),
                               sa.ForeignKey("bgp_speakers.id",
                                             ondelete='CASCADE'),
                               nullable=False)
    dragent = orm.relation(agents_db.Agent)
    agent_id = sa.Column(sa.String(length=36),
                         sa.ForeignKey("agents.id",
                                       ondelete='CASCADE'),
                         primary_key=True)


class BgpDrAgentSchedulerDbMixin(bgp_dras_ext.BgpDrSchedulerPluginBase,
                                 as_db.AgentSchedulerDbMixin):

    bgp_drscheduler = None

    def schedule_unscheduled_bgp_speakers(self, context, host):
        if self.bgp_drscheduler:
            return self.bgp_drscheduler.schedule_unscheduled_bgp_speakers(
                context, host)
        else:
            LOG.warning(_LW("Cannot schedule BgpSpeaker to DrAgent. "
                            "Reason: No scheduler registered."))

    def schedule_bgp_speaker(self, context, created_bgp_speaker):
        if self.bgp_drscheduler:
            agents = self.bgp_drscheduler.schedule(context,
                                                   created_bgp_speaker)
            for agent in agents:
                self._bgp_rpc.bgp_speaker_created(context,
                                                  created_bgp_speaker['id'],
                                                  agent.host)
        else:
            LOG.warning(_LW("Cannot schedule BgpSpeaker to DrAgent. "
                            "Reason: No scheduler registered."))

    def add_bgp_speaker_to_dragent(self, context, agent_id, speaker_id):
        """Associate a BgpDrAgent with a BgpSpeaker."""
        try:
            self._save_bgp_speaker_dragent_binding(context,
                                                   agent_id,
                                                   speaker_id)
        except db_exc.DBDuplicateEntry:
            raise bgp_dras_ext.DrAgentAssociationError(
                    agent_id=agent_id)

        LOG.debug('BgpSpeaker %(bgp_speaker_id)s added to '
                  'BgpDrAgent %(agent_id)s',
                  {'bgp_speaker_id': speaker_id, 'agent_id': agent_id})

    def _save_bgp_speaker_dragent_binding(self, context,
                                          agent_id, speaker_id):
        with context.session.begin(subtransactions=True):
            agent_db = self._get_agent(context, agent_id)
            agent_up = agent_db['admin_state_up']
            is_agent_bgp = (agent_db['agent_type'] ==
                            bgp_consts.AGENT_TYPE_BGP_ROUTING)
            if not is_agent_bgp or not agent_up:
                raise bgp_dras_ext.DrAgentInvalid(id=agent_id)

            binding = BgpSpeakerDrAgentBinding()
            binding.bgp_speaker_id = speaker_id
            binding.agent_id = agent_id
            context.session.add(binding)

        self._bgp_rpc.bgp_speaker_created(context, speaker_id, agent_db.host)

    def remove_bgp_speaker_from_dragent(self, context, agent_id, speaker_id):
        with context.session.begin(subtransactions=True):
            agent_db = self._get_agent(context, agent_id)
            is_agent_bgp = (agent_db['agent_type'] ==
                            bgp_consts.AGENT_TYPE_BGP_ROUTING)
            if not is_agent_bgp:
                raise bgp_dras_ext.DrAgentInvalid(id=agent_id)

            query = context.session.query(BgpSpeakerDrAgentBinding)
            query = query.filter_by(bgp_speaker_id=speaker_id,
                                    agent_id=agent_id)

            num_deleted = query.delete()
            if not num_deleted:
                raise bgp_dras_ext.DrAgentNotHostingBgpSpeaker(
                    bgp_speaker_id=speaker_id,
                    agent_id=agent_id)
            LOG.debug('BgpSpeaker %(bgp_speaker_id)s removed from '
                      'BgpDrAgent %(agent_id)s',
                      {'bgp_speaker_id': speaker_id,
                       'agent_id': agent_id})

        self._bgp_rpc.bgp_speaker_removed(context, speaker_id, agent_db.host)

    def get_dragents_hosting_bgp_speakers(self, context, bgp_speaker_ids,
                                          active=None, admin_state_up=None):
        query = context.session.query(BgpSpeakerDrAgentBinding)
        query = query.options(orm.contains_eager(
                              BgpSpeakerDrAgentBinding.dragent))
        query = query.join(BgpSpeakerDrAgentBinding.dragent)

        if len(bgp_speaker_ids) == 1:
            query = query.filter(
                BgpSpeakerDrAgentBinding.bgp_speaker_id == (
                    bgp_speaker_ids[0]))
        elif bgp_speaker_ids:
            query = query.filter(
                BgpSpeakerDrAgentBinding.bgp_speaker_id in bgp_speaker_ids)
        if admin_state_up is not None:
            query = query.filter(agents_db.Agent.admin_state_up ==
                                 admin_state_up)

        return [binding.dragent
                for binding in query
                if as_db.AgentSchedulerDbMixin.is_eligible_agent(
                                                active, binding.dragent)]

    def get_dragent_bgp_speaker_bindings(self, context):
        return context.session.query(BgpSpeakerDrAgentBinding).all()

    def list_dragent_hosting_bgp_speaker(self, context, speaker_id):
        dragents = self.get_dragents_hosting_bgp_speakers(context,
                                                          [speaker_id])
        agent_ids = [dragent.id for dragent in dragents]
        if not agent_ids:
            return {'agents': []}
        return {'agents': self.get_agents(context, filters={'id': agent_ids})}

    def list_bgp_speaker_on_dragent(self, context, agent_id):
        query = context.session.query(BgpSpeakerDrAgentBinding.bgp_speaker_id)
        query = query.filter_by(agent_id=agent_id)

        bgp_speaker_ids = [item[0] for item in query]
        if not bgp_speaker_ids:
            # Exception will be thrown if the requested agent does not exist.
            self._get_agent(context, agent_id)
            return {'bgp_speakers': []}
        return {'bgp_speakers':
                self.get_bgp_speakers(context,
                                      filters={'id': bgp_speaker_ids})}

    def get_bgp_speakers_for_agent_host(self, context, host):
        agent = self._get_agent_by_type_and_host(
            context, bgp_consts.AGENT_TYPE_BGP_ROUTING, host)
        if not agent.admin_state_up:
            return {}

        query = context.session.query(BgpSpeakerDrAgentBinding)
        query = query.filter(BgpSpeakerDrAgentBinding.agent_id == agent.id)
        try:
            binding = query.one()
        except exc.NoResultFound:
            return []
        bgp_speaker = self.get_bgp_speaker_with_advertised_routes(
                                context, binding['bgp_speaker_id'])
        return [bgp_speaker]

    def get_bgp_speaker_by_speaker_id(self, context, bgp_speaker_id):
        try:
            return self.get_bgp_speaker(context, bgp_speaker_id)
        except exc.NoResultFound:
            return {}

    def get_bgp_peer_by_peer_id(self, context, bgp_peer_id):
        try:
            return self.get_bgp_peer(context, bgp_peer_id)
        except exc.NoResultFound:
            return {}
