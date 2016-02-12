# Copyright 2016 Hewlett Packard Enterprise Development Company LP
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
from oslo_log import log as logging
from oslo_utils import importutils

from neutron.api.rpc.agentnotifiers import bgp_dr_rpc_agent_api
from neutron.api.rpc.handlers import bgp_speaker_rpc as bs_rpc
from neutron.common import rpc as n_rpc
from neutron.db import bgp_db
from neutron.db import bgp_dragentscheduler_db
from neutron.extensions import bgp as bgp_ext
from neutron.extensions import bgp_dragentscheduler as dras_ext
from neutron.services.bgp.common import constants as bgp_consts
from neutron.services import service_base

PLUGIN_NAME = bgp_ext.BGP_EXT_ALIAS + '_svc_plugin'
LOG = logging.getLogger(__name__)


class BgpPlugin(service_base.ServicePluginBase,
                bgp_db.BgpDbMixin,
                bgp_dragentscheduler_db.BgpDrAgentSchedulerDbMixin):

    supported_extension_aliases = [bgp_ext.BGP_EXT_ALIAS,
                                   dras_ext.BGP_DRAGENT_SCHEDULER_EXT_ALIAS]

    def __init__(self):
        super(BgpPlugin, self).__init__()
        self.bgp_drscheduler = importutils.import_object(
            cfg.CONF.bgp_drscheduler_driver)
        self._setup_rpc()

    def get_plugin_name(self):
        return PLUGIN_NAME

    def get_plugin_type(self):
        return bgp_ext.BGP_EXT_ALIAS

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("BGP dynamic routing service for announcement of next-hops "
                "for tenant networks, floating IP's, and DVR host routes.")

    def _setup_rpc(self):
        self.topic = bgp_consts.BGP_PLUGIN
        self.conn = n_rpc.create_connection()
        self.agent_notifiers[bgp_consts.AGENT_TYPE_BGP_ROUTING] = (
            bgp_dr_rpc_agent_api.BgpDrAgentNotifyApi()
        )
        self._bgp_rpc = self.agent_notifiers[bgp_consts.AGENT_TYPE_BGP_ROUTING]
        self.endpoints = [bs_rpc.BgpSpeakerRpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        self.conn.consume_in_threads()

    def add_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        ret_value = super(BgpPlugin, self).add_bgp_peer(context,
                                                        bgp_speaker_id,
                                                        bgp_peer_info)
        hosted_bgp_dragents = self.get_dragents_hosting_bgp_speakers(
                                                             context,
                                                             [bgp_speaker_id])
        for agent in hosted_bgp_dragents:
            self._bgp_rpc.bgp_peer_associated(context, bgp_speaker_id,
                                              ret_value['bgp_peer_id'],
                                              agent.host)
        return ret_value

    def remove_bgp_peer(self, context, bgp_speaker_id, bgp_peer_info):
        hosted_bgp_dragents = self.get_dragents_hosting_bgp_speakers(
            context, [bgp_speaker_id])

        ret_value = super(BgpPlugin, self).remove_bgp_peer(context,
                                                           bgp_speaker_id,
                                                           bgp_peer_info)

        for agent in hosted_bgp_dragents:
            self._bgp_rpc.bgp_peer_disassociated(context,
                                                 bgp_speaker_id,
                                                 ret_value['bgp_peer_id'],
                                                 agent.host)
