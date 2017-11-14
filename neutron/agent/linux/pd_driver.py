# Copyright 2015 Cisco Systems
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

from neutron.conf.agent import common as agent_conf

agent_conf.register_pddriver_opts()


@six.add_metaclass(abc.ABCMeta)
class PDDriverBase(object):

    def __init__(self, router_id, subnet_id, ri_ifname):
        self.router_id = router_id
        self.subnet_id = subnet_id
        self.ri_ifname = ri_ifname

    @abc.abstractmethod
    def enable(self, pmon, router_ns, ex_gw_ifname, lla):
        """Enable IPv6 Prefix Delegation for this PDDriver on the given
        external interface, with the given link local address
        """

    @abc.abstractmethod
    def disable(self, pmon, router_ns):
        """Disable IPv6 Prefix Delegation for this PDDriver
        """

    @abc.abstractmethod
    def get_prefix(self):
        """Get the current assigned prefix for this PDDriver from the PD agent.
        If no prefix is currently assigned, return
        neutron_lib.constants.PROVISIONAL_IPV6_PD_PREFIX
        """

    @staticmethod
    @abc.abstractmethod
    def get_sync_data():
        """Get the latest router_id, subnet_id, and ri_ifname from the PD agent
        so that the PDDriver can be kept up to date
        """
