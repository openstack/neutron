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

import abc
import six
import webob

from oslo_log import log as logging

from neutron.api import extensions
from neutron.api.v2 import base
from neutron.api.v2 import resource
from neutron.common import exceptions
from neutron.extensions import agent
from neutron.extensions import bgp as bgp_ext
from neutron._i18n import _, _LE
from neutron import manager
from neutron import wsgi


LOG = logging.getLogger(__name__)

BGP_DRAGENT_SCHEDULER_EXT_ALIAS = 'bgp_dragent_scheduler'
BGP_DRINSTANCE = 'bgp-drinstance'
BGP_DRINSTANCES = BGP_DRINSTANCE + 's'
BGP_DRAGENT = 'bgp-dragent'
BGP_DRAGENTS = BGP_DRAGENT + 's'


class DrAgentInvalid(agent.AgentNotFound):
    message = _("BgpDrAgent %(id)s is invalid or has been disabled.")


class DrAgentNotHostingBgpSpeaker(exceptions.NotFound):
    message = _("BGP speaker %(bgp_speaker_id)s is not hosted "
                "by the BgpDrAgent %(agent_id)s.")


class DrAgentAssociationError(exceptions.Conflict):
    message = _("BgpDrAgent %(agent_id)s is already associated "
                "to a BGP speaker.")


class BgpDrSchedulerController(wsgi.Controller):
    """Schedule BgpSpeaker for a BgpDrAgent"""
    def get_plugin(self):
        plugin = manager.NeutronManager.get_service_plugins().get(
            bgp_ext.BGP_EXT_ALIAS)
        if not plugin:
            LOG.error(_LE('No plugin for BGP routing registered'))
            msg = _('The resource could not be found.')
            raise webob.exc.HTTPNotFound(msg)
        return plugin

    def index(self, request, **kwargs):
        plugin = self.get_plugin()
        return plugin.list_bgp_speaker_on_dragent(
            request.context, kwargs['agent_id'])

    def create(self, request, body, **kwargs):
        plugin = self.get_plugin()
        return plugin.add_bgp_speaker_to_dragent(
            request.context,
            kwargs['agent_id'],
            body['bgp_speaker_id'])

    def delete(self, request, id, **kwargs):
        plugin = self.get_plugin()
        return plugin.remove_bgp_speaker_from_dragent(
            request.context, kwargs['agent_id'], id)


class BgpDrAgentController(wsgi.Controller):
    def get_plugin(self):
        plugin = manager.NeutronManager.get_service_plugins().get(
            bgp_ext.BGP_EXT_ALIAS)
        if not plugin:
            LOG.error(_LE('No plugin for BGP routing registered'))
            msg = _LE('The resource could not be found.')
            raise webob.exc.HTTPNotFound(msg)
        return plugin

    def index(self, request, **kwargs):
        plugin = manager.NeutronManager.get_service_plugins().get(
            bgp_ext.BGP_EXT_ALIAS)
        return plugin.list_dragent_hosting_bgp_speaker(
            request.context, kwargs['bgp_speaker_id'])


class Bgp_dragentscheduler(extensions.ExtensionDescriptor):
    """Extension class supporting Dynamic Routing scheduler.
    """
    @classmethod
    def get_name(cls):
        return "BGP Dynamic Routing Agent Scheduler"

    @classmethod
    def get_alias(cls):
        return BGP_DRAGENT_SCHEDULER_EXT_ALIAS

    @classmethod
    def get_description(cls):
        return "Schedules BgpSpeakers on BgpDrAgent"

    @classmethod
    def get_updated(cls):
        return "2015-07-30T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        exts = []
        parent = dict(member_name="agent",
                      collection_name="agents")

        controller = resource.Resource(BgpDrSchedulerController(),
                                       base.FAULT_MAP)
        exts.append(extensions.ResourceExtension(BGP_DRINSTANCES,
                                                 controller, parent))

        parent = dict(member_name="bgp_speaker",
                      collection_name="bgp-speakers")
        controller = resource.Resource(BgpDrAgentController(),
                                       base.FAULT_MAP)
        exts.append(extensions.ResourceExtension(BGP_DRAGENTS,
                                                 controller, parent))
        return exts

    def get_extended_resources(self, version):
        return {}


@six.add_metaclass(abc.ABCMeta)
class BgpDrSchedulerPluginBase(object):
    """REST API to operate BGP dynamic routing agent scheduler.

    All the methods must be executed in admin context.
    """
    def get_plugin_description(self):
        return "Neutron BGP dynamic routing scheduler Plugin"

    def get_plugin_type(self):
        return bgp_ext.BGP_EXT_ALIAS

    @abc.abstractmethod
    def add_bgp_speaker_to_dragent(self, context, agent_id, speaker_id):
        pass

    @abc.abstractmethod
    def remove_bgp_speaker_from_dragent(self, context, agent_id, speaker_id):
        pass

    @abc.abstractmethod
    def list_dragent_hosting_bgp_speaker(self, context, speaker_id):
        pass

    @abc.abstractmethod
    def list_bgp_speaker_on_dragent(self, context, agent_id):
        pass

    @abc.abstractmethod
    def get_bgp_speakers_for_agent_host(self, context, host):
        pass

    @abc.abstractmethod
    def get_bgp_speaker_by_speaker_id(self, context, speaker_id):
        pass

    @abc.abstractmethod
    def get_bgp_peer_by_peer_id(self, context, bgp_peer_id):
        pass
