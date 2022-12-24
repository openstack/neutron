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

from packaging import version

from neutron_lib import exceptions
from oslo_log import log as logging

from neutron.agent.linux import utils as agent_utils

LOG = logging.getLogger(__name__)


# NOTE: Runtime checks are strongly discouraged in favor of sanity checks
#       which would be run at system setup time. Please consider writing a
#       sanity check instead.

def dnsmasq_host_tag_support():
    cmd = ['dnsmasq', '--test', '--dhcp-host=tag:foo']
    env = {'LC_ALL': 'C', 'PATH': '/sbin:/usr/sbin'}
    try:
        agent_utils.execute(cmd, addl_env=env, log_fail_as_error=False)
    except exceptions.ProcessExecutionError:
        return False
    return True


def get_keepalived_version():
    cmd = ['keepalived', '--version']
    env = {'LC_ALL': 'C', 'PATH': '/sbin:/usr/sbin'}
    try:
        # keepalived --version returns with stderr only
        res = agent_utils.execute(cmd, addl_env=env, log_fail_as_error=False,
                                  return_stderr=True)
        # First line is the interesting one here from stderr
        version_line = res[1].split('\n')[0]
        keepalived_version = version.parse(version_line.split()[1])
        return keepalived_version
    except exceptions.ProcessExecutionError:
        LOG.exception("Failed to get keepalived version")
        return False


def keepalived_use_no_track_support():

    keepalived_with_track = version.parse('2.0.3')
    keepalived_version = get_keepalived_version()
    if keepalived_version:
        return keepalived_version >= keepalived_with_track
    return False
