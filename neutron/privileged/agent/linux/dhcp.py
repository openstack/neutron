# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_concurrency import processutils

from neutron import privileged


@privileged.dhcp_release_cmd.entrypoint
def dhcp_release(interface_name, ip_address, mac_address, client_id,
                 namespace=None):
    cmd = []
    if namespace:
        cmd += ['ip', 'netns', 'exec', namespace]
    cmd += ['dhcp_release', interface_name, ip_address, mac_address]
    if client_id:
        cmd.append(client_id)
    log_errors = processutils.LOG_FINAL_ERROR
    return processutils.execute(*cmd, log_errors=log_errors)


@privileged.dhcp_release_cmd.entrypoint
def dhcp_release6(interface_name, ip_address, client_id, server_id, iaid,
                  namespace=None):
    cmd = []
    if namespace:
        cmd += ['ip', 'netns', 'exec', namespace]
    cmd += ['dhcp_release6', '--iface', interface_name, '--ip', ip_address,
            '--client-id', client_id, '--server-id', server_id, '--iaid', iaid]
    log_errors = processutils.LOG_FINAL_ERROR
    return processutils.execute(*cmd, log_errors=log_errors)


@privileged.dhcp_release_cmd.entrypoint
def dhcp_release6_supported():
    cmd = ['dhcp_release6', '--help']
    result = processutils.execute(*cmd, check_exit_code=False,
                                  env_variables={'LC_ALL': 'C'})
    return not bool(result[1])
