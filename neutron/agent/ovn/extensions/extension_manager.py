# Copyright (c) 2023 Red Hat, Inc.
# All Rights Reserved.
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

import abc
import threading

from neutron_lib.agent import extension
from neutron_lib import exceptions
from oslo_log import log as logging

from neutron._i18n import _
from neutron.agent import agent_extensions_manager as agent_ext_mgr


LOG = logging.getLogger(__name__)
OVN_AGENT_EXT_MANAGER_NAMESPACE = 'neutron.agent.ovn.extensions'


class ConfigException(exceptions.NeutronException):
    """Misconfiguration of the OVN Neutron Agent"""
    message = _('Error configuring the OVN Neutron Agent: %(description)s.')


class OVNAgentExtensionManager(agent_ext_mgr.AgentExtensionsManager):

    def __init__(self, conf):
        super().__init__(conf, OVN_AGENT_EXT_MANAGER_NAMESPACE)
        for ext in self:
            if not isinstance(ext.obj, OVNAgentExtension):
                desc = ('Extension %s class is not inheriting from '
                        '"OVNAgentExtension"')
                raise ConfigException(description=desc)

    def start(self):
        """Start the extensions, once the OVN agent has been initialized."""
        for ext in self:
            ext.obj.start()
            LOG.info('Extension manager: %s started', ext.obj.name)


class OVNAgentExtension(extension.AgentExtension, metaclass=abc.ABCMeta):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.agent_api = None
        self._is_started = False

    @property
    @abc.abstractmethod
    def name(self):
        pass

    def initialize(self, *args):
        """Initialize agent extension."""
        pass

    def consume_api(self, agent_api):
        """Configure the Agent API.

        Allows an extension to gain access to resources internal to the
        neutron agent and otherwise unavailable to the extension.
        """
        self.agent_api = agent_api

    def start(self):
        """Start the extension, once the OVN agent has been initialized.

        This method executes any action needed after the initialization of the
        OVN agent and the extension manager API. It is executed at the end of
        the OVN agent ``start`` method.
        """
        self._is_started = True

    @property
    def is_started(self):
        return self._is_started

    @property
    @abc.abstractmethod
    def ovs_idl_events(self):
        pass

    @property
    @abc.abstractmethod
    def nb_idl_tables(self):
        pass

    @property
    @abc.abstractmethod
    def nb_idl_events(self):
        pass

    @property
    @abc.abstractmethod
    def sb_idl_tables(self):
        pass

    @property
    @abc.abstractmethod
    def sb_idl_events(self):
        pass


class OVNAgentExtensionAPI(object):
    """Implements the OVN Neutron Agent API"""

    def __init__(self):
        self._nb_idl = None
        self._sb_idl = None
        self._has_chassis_private = None
        self._ovs_idl = None
        self.sb_post_fork_event = threading.Event()
        self.sb_post_fork_event.clear()
        self.nb_post_fork_event = threading.Event()
        self.nb_post_fork_event.clear()

    @property
    def ovs_idl(self):
        return self._ovs_idl

    @ovs_idl.setter
    def ovs_idl(self, val):
        self._ovs_idl = val

    @property
    def nb_idl(self):
        if not self._nb_idl:
            self.nb_post_fork_event.wait()
        return self._nb_idl

    @nb_idl.setter
    def nb_idl(self, val):
        self.nb_post_fork_event.set()
        self._nb_idl = val

    @property
    def sb_idl(self):
        if not self._sb_idl:
            self.sb_post_fork_event.wait()
        return self._sb_idl

    @sb_idl.setter
    def sb_idl(self, val):
        self.sb_post_fork_event.set()
        self._sb_idl = val
