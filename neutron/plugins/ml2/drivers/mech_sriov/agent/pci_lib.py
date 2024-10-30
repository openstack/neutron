# Copyright 2014 Mellanox Technologies, Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import enum

from oslo_log import log as logging

from neutron.agent.linux import ip_lib


LOG = logging.getLogger(__name__)


class LinkState(enum.Enum):
    auto = 0
    enable = 1
    disable = 2


class PciDeviceIPWrapper(ip_lib.IPWrapper):
    """Wrapper class for ip link commands related to virtual functions."""

    def __init__(self, dev_name):
        super().__init__()
        self.dev_name = dev_name

    def get_assigned_macs(self, vf_list):
        """Get assigned mac addresses for vf list.

        @param vf_list: list of vf indexes
        @return: dict mapping of vf to mac
        """
        ip = self.device(self.dev_name)
        vfs = ip.link.get_vfs()
        vf_to_mac_mapping = {}
        for vf_num in vf_list:
            if vfs.get(vf_num):
                vf_to_mac_mapping[vf_num] = vfs[vf_num]['mac']

        return vf_to_mac_mapping

    def get_vf_state(self, vf_index):
        """Get vf state {enable/disable/auto}

        @param vf_index: vf index
        """
        ip = self.device(self.dev_name)
        vfs = ip.link.get_vfs()
        vf = vfs.get(vf_index)
        if vf:
            return LinkState(int(vf['link_state'])).name

        return LinkState.disable.name

    def set_vf_state(self, vf_index, state, auto=False):
        """sets vf state.

        @param vf_index: vf index
        @param state: required state {True: enable (1)
                                      False: disable (2)}
        @param auto: set link_state to auto (0)
        """
        ip = self.device(self.dev_name)
        # NOTE(ralonsoh): the state=False --> "disable" (2) has precedence over
        # "auto" (0) and "enable" (1).
        if state is False:
            link_state = 2
        elif auto:
            link_state = 0
        else:
            link_state = 1
        vf_config = {'vf': vf_index, 'link_state': link_state}
        ip.link.set_vf_feature(vf_config)

    def set_vf_spoofcheck(self, vf_index, enabled):
        """sets vf spoofcheck

        @param vf_index: vf index
        @param enabled: True to enable (1) spoof checking,
                        False to disable (0)
        """
        ip = self.device(self.dev_name)
        vf_config = {'vf': vf_index, 'spoofchk': int(enabled)}
        ip.link.set_vf_feature(vf_config)

    def set_vf_rate(self, vf_index, rates):
        """sets vf rates.
        @param vf_index: vf index
        @param rates: dictionary with rate type (str) and the value (int)
                      in Mbps. Example:
                        {'max_tx_rate': 20, 'min_tx_rate': 10}
                        {'max_tx_rate': 30}
                        {'min_tx_rate': 5}
        """
        ip = self.device(self.dev_name)
        vf_config = {'vf': vf_index, 'rate': rates}
        try:
            ip.link.set_vf_feature(vf_config)
        except ip_lib.InvalidArgument:
            # NOTE(ralonsoh): some NICs do not support "min_tx_rate" parameter.
            # https://bugs.launchpad.net/neutron/+bug/1918464
            LOG.error('Device %(device)s does not support ip-link vf '
                      '"min_tx_rate" parameter. Rates: %(rates)s',
                      {'device': self.dev_name, 'rates': rates})
