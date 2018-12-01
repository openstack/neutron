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

import re

from oslo_log import log as logging

from neutron.agent.linux import ip_lib
from neutron.plugins.ml2.drivers.mech_sriov.agent.common \
    import exceptions as exc

LOG = logging.getLogger(__name__)


class LinkState(object):
    ENABLE = "enable"
    DISABLE = "disable"
    AUTO = "auto"


class PciDeviceIPWrapper(ip_lib.IPWrapper):
    """Wrapper class for ip link commands.

    wrapper for getting/setting pci device details using ip link...
    """
    VF_PATTERN = r"^vf\s+(?P<vf_index>\d+)\s+"
    MAC_PATTERN = r"MAC\s+(?P<mac>[a-fA-F0-9:]+),"
    STATE_PATTERN = r"\s+link-state\s+(?P<state>\w+)"
    ANY_PATTERN = ".*,"
    MACVTAP_PATTERN = r".*macvtap[0-9]+@(?P<vf_interface>[a-zA-Z0-9_]+):"

    VF_LINE_FORMAT = VF_PATTERN + MAC_PATTERN + ANY_PATTERN + STATE_PATTERN
    VF_DETAILS_REG_EX = re.compile(VF_LINE_FORMAT)
    MACVTAP_REG_EX = re.compile(MACVTAP_PATTERN)

    IP_LINK_OP_NOT_SUPPORTED = 'RTNETLINK answers: Operation not supported'

    def __init__(self, dev_name):
        super(PciDeviceIPWrapper, self).__init__()
        self.dev_name = dev_name

    def _set_feature(self, vf_index, feature, value):
        """Sets vf feature

        Checks if the feature is not supported or there's some
        general error during ip link invocation and raises
        exception accordingly.

        :param vf_index: vf index
        :param feature: name of a feature to be passed to ip link,
                        such as 'state' or 'spoofchk'
        :param value: value of the feature setting
        """
        try:
            self._as_root([], "link", ("set", self.dev_name, "vf",
                                       str(vf_index), feature, value))
        except Exception as e:
            if self.IP_LINK_OP_NOT_SUPPORTED in str(e):
                raise exc.IpCommandOperationNotSupportedError(
                    dev_name=self.dev_name)
            else:
                raise exc.IpCommandDeviceError(dev_name=self.dev_name,
                                               reason=str(e))

    def get_assigned_macs(self, vf_list):
        """Get assigned mac addresses for vf list.

        @param vf_list: list of vf indexes
        @return: dict mapping of vf to mac
        """
        try:
            out = self._as_root([], "link", ("show", self.dev_name))
        except Exception as e:
            LOG.exception("Failed executing ip command")
            raise exc.IpCommandDeviceError(dev_name=self.dev_name,
                                           reason=e)
        vf_to_mac_mapping = {}
        vf_lines = self._get_vf_link_show(vf_list, out)
        if vf_lines:
            for vf_line in vf_lines:
                vf_details = self._parse_vf_link_show(vf_line)
                if vf_details:
                    vf_num = vf_details.get('vf')
                    vf_mac = vf_details.get("MAC")
                    vf_to_mac_mapping[vf_num] = vf_mac
        return vf_to_mac_mapping

    def get_vf_state(self, vf_index):
        """Get vf state {enable/disable/auto}

        @param vf_index: vf index
        """
        try:
            out = self._as_root([], "link", ("show", self.dev_name))
        except Exception as e:
            LOG.exception("Failed executing ip command")
            raise exc.IpCommandDeviceError(dev_name=self.dev_name,
                                           reason=e)
        vf_lines = self._get_vf_link_show([vf_index], out)
        if vf_lines:
            vf_details = self._parse_vf_link_show(vf_lines[0])
            if vf_details:
                state = vf_details.get("link-state",
                                       LinkState.DISABLE)
            if state in (LinkState.AUTO, LinkState.ENABLE):
                return state
        return LinkState.DISABLE

    def set_vf_state(self, vf_index, state, auto=False):
        """sets vf state.

        @param vf_index: vf index
        @param state: required state {True/False}
        """
        if auto:
            status_str = LinkState.AUTO
        else:
            status_str = LinkState.ENABLE if state else \
                LinkState.DISABLE
        self._set_feature(vf_index, "state", status_str)

    def set_vf_spoofcheck(self, vf_index, enabled):
        """sets vf spoofcheck

        @param vf_index: vf index
        @param enabled: True to enable spoof checking,
                        False to disable
        """
        setting = "on" if enabled else "off"
        self._set_feature(vf_index, "spoofchk", setting)

    def set_vf_rate(self, vf_index, rate_type, rate_value):
        """sets vf rate.

        @param vf_index: vf index
        @param rate_type: vf rate type ('rate', 'min_tx_rate')
        @param rate_value: vf rate in Mbps
        """
        self._set_feature(vf_index, rate_type, str(rate_value))

    def _get_vf_link_show(self, vf_list, link_show_out):
        """Get link show output for VFs

        get vf link show command output filtered by given vf list
        @param vf_list: list of vf indexes
        @param link_show_out: link show command output
        @return: list of output rows regarding given vf_list
        """
        vf_lines = []
        for line in link_show_out.split("\n"):
            line = line.strip()
            if line.startswith("vf"):
                details = line.split()
                index = int(details[1])
                if index in vf_list:
                    vf_lines.append(line)
        if not vf_lines:
            LOG.warning("Cannot find vfs %(vfs)s in device %(dev_name)s",
                        {'vfs': vf_list, 'dev_name': self.dev_name})
        return vf_lines

    def _parse_vf_link_show(self, vf_line):
        """Parses vf link show command output line.

        @param vf_line: link show vf line
        """
        vf_details = {}
        pattern_match = self.VF_DETAILS_REG_EX.match(vf_line)
        if pattern_match:
            vf_details["vf"] = int(pattern_match.group("vf_index"))
            vf_details["MAC"] = pattern_match.group("mac")
            vf_details["link-state"] = pattern_match.group("state")
        else:
            LOG.warning("failed to parse vf link show line %(line)s: "
                        "for %(device)s",
                        {'line': vf_line, 'device': self.dev_name})
        return vf_details

    def link_show(self):
        try:
            out = self._as_root([], "link", ("show", ))
        except Exception as e:
            LOG.error("Failed executing ip command: %s", e)
            raise exc.IpCommandError(reason=e)
        return out

    @classmethod
    def is_macvtap_assigned(cls, ifname, ip_link_show_output):
        """Check if vf has macvtap interface assigned

        Parses the output of ip link show command and checks
        if macvtap[0-9]+@<vf interface> regex matches the
        output.
        @param ifname: vf interface name
        @param ip_link_show_output: 'ip link show' result to parse
        @return: True on match otherwise False
        """
        for line in ip_link_show_output.splitlines():
            pattern_match = cls.MACVTAP_REG_EX.match(line)
            if pattern_match:
                if ifname == pattern_match.group('vf_interface'):
                    return True
        return False
