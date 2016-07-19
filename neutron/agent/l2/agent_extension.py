# Copyright (c) 2015 Mellanox Technologies, Ltd
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

import six

from neutron.agent.l2 import l2_agent_extension


@six.add_metaclass(abc.ABCMeta)
class AgentCoreResourceExtension(l2_agent_extension.L2AgentExtension):
    """This is a shim around L2AgentExtension class.  It is intended for use by
    out of tree extensions that were inheriting AgentCoreResourceExtension.
    """
