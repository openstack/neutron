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

from neutron_lib import exceptions as n_exc
from oslo_log import log as logging

from neutron._i18n import _
from neutron.agent.linux import utils


LOG = logging.getLogger(__name__)


class IpLinkSupportError(n_exc.NeutronException):
    pass


class UnsupportedIpLinkCommand(IpLinkSupportError):
    message = _("ip link command is not supported: %(reason)s")


class InvalidIpLinkCapability(IpLinkSupportError):
    message = _("ip link capability %(capability)s is not supported")


class IpLinkConstants(object):
    IP_LINK_CAPABILITY_STATE = "state"
    IP_LINK_CAPABILITY_VLAN = "vlan"
    IP_LINK_CAPABILITY_RATE = "rate"
    IP_LINK_CAPABILITY_MIN_TX_RATE = "min_tx_rate"
    IP_LINK_CAPABILITY_SPOOFCHK = "spoofchk"
    IP_LINK_SUB_CAPABILITY_QOS = "qos"


class IpLinkSupport(object):
    VF_BLOCK_REGEX = r"\[ vf NUM(?P<vf_block>.*) \] \]"

    CAPABILITY_REGEX = r"\[ %s (.*)"
    SUB_CAPABILITY_REGEX = r"\[ %(cap)s (.*) \[ %(subcap)s (.*)"

    @classmethod
    def get_vf_mgmt_section(cls):
        """Parses ip link help output, and gets vf block"""

        output = cls._get_ip_link_output()
        vf_block_pattern = re.search(cls.VF_BLOCK_REGEX,
                                     output,
                                     re.DOTALL | re.MULTILINE)
        if vf_block_pattern:
            return vf_block_pattern.group("vf_block")

    @classmethod
    def vf_mgmt_capability_supported(cls, vf_section, capability,
                                     subcapability=None):
        """Validate vf capability support

        Checks if given vf capability (and sub capability
        if given) supported
        :param vf_section: vf Num block content
        :param capability: for example: vlan, rate, spoofchk, state
        :param subcapability: for example: qos
        """
        if not vf_section:
            return False
        if subcapability:
            regex = cls.SUB_CAPABILITY_REGEX % {"cap": capability,
                                                "subcap": subcapability}
        else:
            regex = cls.CAPABILITY_REGEX % capability
        pattern_match = re.search(regex, vf_section,
                                  re.DOTALL | re.MULTILINE)
        return pattern_match is not None

    @classmethod
    def _get_ip_link_output(cls):
        """Gets the output of the ip link help command

        Runs ip link help command and stores its output
        Note: ip link help return error and writes its output to stderr
                so we get the output from there. however, if this issue
                will be solved and the command will write to stdout, we
                will get the output from there too.
        """
        try:
            ip_cmd = ['ip', 'link', 'help']
            _stdout, _stderr = utils.execute(
                ip_cmd,
                check_exit_code=False,
                return_stderr=True,
                log_fail_as_error=False)
        except Exception as e:
            LOG.exception("Failed executing ip command")
            raise UnsupportedIpLinkCommand(reason=e)
        return _stdout or _stderr
