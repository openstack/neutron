# Copyright (c) 2014 OpenStack Foundation.
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

from neutron_lib import exceptions
from oslo_log import log as logging

from neutron.agent.linux import utils as agent_utils

LOG = logging.getLogger(__name__)


# NOTE: Runtime checks are strongly discouraged in favor of sanity checks
#       which would be run at system setup time. Please consider writing a
#       sanity check instead.


def dhcp_release6_supported():
    try:
        cmd = ['dhcp_release6', '--help']
        env = {'LC_ALL': 'C'}
        agent_utils.execute(cmd, addl_env=env)
    except (OSError, RuntimeError, IndexError, ValueError) as e:
        LOG.debug("Exception while checking dhcp_release6. "
                  "Exception: %s", e)
        return False
    return True


def dnsmasq_host_tag_support():
    cmd = ['dnsmasq', '--test', '--dhcp-host=tag:foo']
    env = {'LC_ALL': 'C', 'PATH': '/sbin:/usr/sbin'}
    try:
        agent_utils.execute(cmd, addl_env=env, log_fail_as_error=False)
    except exceptions.ProcessExecutionError:
        return False
    return True
