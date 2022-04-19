# Copyright (c) 2012 OpenStack Foundation.
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

import itertools
import re
import signal
import time

from neutron_lib import constants
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from neutron.agent.common import ovs_lib
from neutron.agent.l3 import dvr_fip_ns
from neutron.agent.l3 import dvr_snat_ns
from neutron.agent.l3 import namespaces
from neutron.agent.linux import dhcp
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import config
from neutron.conf.agent import cmd
from neutron.conf.agent import common as agent_config
from neutron.conf.agent import dhcp as dhcp_config
from neutron.privileged.agent.linux import utils as priv_utils

LOG = logging.getLogger(__name__)
NS_PREFIXES = {
    'dhcp': [dhcp.NS_PREFIX],
    'l3': [namespaces.NS_PREFIX, dvr_snat_ns.SNAT_NS_PREFIX,
           dvr_fip_ns.FIP_NS_PREFIX],
}
SIGTERM_WAITTIME = 10


class PidsInNamespaceException(Exception):
    pass


class FakeDhcpPlugin(object):
    """Fake RPC plugin to bypass any RPC calls."""
    def __getattribute__(self, name):
        def fake_method(*args):
            pass
        return fake_method


def setup_conf():
    """Setup the cfg for the clean up utility.

    Use separate setup_conf for the utility because there are many options
    from the main config that do not apply during clean-up.
    """

    conf = cfg.CONF
    config.register_common_config_options()
    cmd.register_cmd_opts(cmd.netns_opts, conf)
    agent_config.register_interface_driver_opts_helper(conf)
    dhcp_config.register_agent_dhcp_opts(conf)
    agent_config.register_interface_opts()
    return conf


def _get_dhcp_process_monitor(config):
    return external_process.ProcessMonitor(config=config,
                                           resource_type='dhcp')


def kill_dhcp(conf, namespace):
    """Disable DHCP for a network if DHCP is still active."""
    network_id = namespace.replace(dhcp.NS_PREFIX, '')

    dhcp_driver = importutils.import_object(
        conf.dhcp_driver,
        conf=conf,
        process_monitor=_get_dhcp_process_monitor(conf),
        network=dhcp.NetModel({'id': network_id}),
        plugin=FakeDhcpPlugin())

    if dhcp_driver.active:
        dhcp_driver.disable()


def eligible_for_deletion(conf, namespace, force=False):
    """Determine whether a namespace is eligible for deletion.

    Eligibility is determined by having only the lo device or if force
    is passed as a parameter.
    """

    if conf.agent_type:
        prefixes = NS_PREFIXES.get(conf.agent_type)
    else:
        prefixes = itertools.chain(*NS_PREFIXES.values())
    ns_mangling_pattern = '(%s%s)' % ('|'.join(prefixes),
                                      constants.UUID_PATTERN)

    # filter out namespaces without UUID as the name
    if not re.match(ns_mangling_pattern, namespace):
        return False

    ip = ip_lib.IPWrapper(namespace=namespace)
    return force or ip.namespace_is_empty()


def unplug_device(device):
    orig_log_fail_as_error = device.get_log_fail_as_error()
    device.set_log_fail_as_error(False)
    try:
        device.link.delete()
    except RuntimeError:
        device.set_log_fail_as_error(orig_log_fail_as_error)
        # Maybe the device is OVS port, so try to delete
        ovs = ovs_lib.BaseOVS()
        bridge_name = ovs.get_bridge_for_iface(device.name)
        if bridge_name:
            bridge = ovs_lib.OVSBridge(bridge_name)
            bridge.delete_port(device.name)
        else:
            LOG.debug('Unable to find bridge for device: %s', device.name)
    finally:
        device.set_log_fail_as_error(orig_log_fail_as_error)


def wait_until_no_listen_pids_namespace(namespace, timeout=SIGTERM_WAITTIME):
    """Poll listening processes within the given namespace.

    If after timeout seconds, there are remaining processes in the namespace,
    then a PidsInNamespaceException will be thrown.
    """
    # NOTE(dalvarez): This function can block forever if
    # find_listen_pids_in_namespace never returns which is really unlikely. We
    # can't use wait_until_true because we might get interrupted by eventlet
    # Timeout during our I/O with rootwrap daemon and that will lead to errors
    # in subsequent calls to utils.execute grabbing always the output of the
    # previous command
    start = end = time.time()
    while end - start < timeout:
        if not priv_utils.find_listen_pids_namespace(namespace):
            return
        time.sleep(1)
        end = time.time()
    raise PidsInNamespaceException


def _kill_listen_processes(namespace, force=False):
    """Identify all listening processes within the given namespace.

    Then, for each one, find its top parent with same cmdline (in case this
    process forked) and issue a SIGTERM to all of them. If force is True,
    then a SIGKILL will be issued to all parents and all their children. Also,
    this function returns the number of listening processes.
    """
    pids = priv_utils.find_listen_pids_namespace(namespace)
    pids_to_kill = {utils.find_fork_top_parent(pid) for pid in pids}
    kill_signal = signal.SIGTERM
    if force:
        kill_signal = signal.SIGKILL
        children = [utils.find_child_pids(pid, True) for pid in pids_to_kill]
        pids_to_kill.update(itertools.chain.from_iterable(children))

    for pid in pids_to_kill:
        # Throw a warning since this particular cleanup may need a specific
        # implementation in the right module. Ideally, netns_cleanup wouldn't
        # kill any processes as the responsible module should've killed them
        # before cleaning up the namespace
        LOG.warning("Killing (%(signal)d) [%(pid)s] %(cmdline)s",
                    {'signal': kill_signal,
                     'pid': pid,
                     'cmdline': ' '.join(utils.get_cmdline_from_pid(pid))[:80]
                     })
        try:
            utils.kill_process(pid, kill_signal, run_as_root=True)
        except Exception as ex:
            LOG.error('An error occurred while killing '
                      '[%(pid)s]: %(msg)s', {'pid': pid, 'msg': ex})
    return len(pids)


def kill_listen_processes(namespace):
    """Kill all processes listening within the given namespace.

    First it tries to kill them using SIGTERM, waits until they die gracefully
    and then kills remaining processes (if any) with SIGKILL
    """
    if _kill_listen_processes(namespace, force=False):
        try:
            wait_until_no_listen_pids_namespace(namespace)
        except PidsInNamespaceException:
            _kill_listen_processes(namespace, force=True)
            # Allow some time for remaining processes to die
            wait_until_no_listen_pids_namespace(namespace)


def destroy_namespace(conf, namespace, force=False):
    """Destroy a given namespace.

    If force is True, then dhcp (if it exists) will be disabled and all
    devices will be forcibly removed.
    """

    try:
        ip = ip_lib.IPWrapper(namespace=namespace)

        if force:
            kill_dhcp(conf, namespace)
            # NOTE: The dhcp driver will remove the namespace if is it empty,
            # so a second check is required here.
            if ip.netns.exists(namespace):
                try:
                    kill_listen_processes(namespace)
                except PidsInNamespaceException:
                    # This is unlikely since, at this point, we have SIGKILLed
                    # all remaining processes but if there are still some, log
                    # the error and continue with the cleanup
                    LOG.error('Not all processes were killed in %s',
                              namespace)
                for device in ip.get_devices():
                    unplug_device(device)

        ip.garbage_collect_namespace()
    except Exception:
        LOG.exception('Error unable to destroy namespace: %s', namespace)


def cleanup_network_namespaces(conf):
    # Identify namespaces that are candidates for deletion.
    candidates = [ns for ns in
                  ip_lib.list_network_namespaces()
                  if eligible_for_deletion(conf, ns, conf.force)]

    if candidates:
        time.sleep(2)

        for namespace in candidates:
            destroy_namespace(conf, namespace, conf.force)


def main():
    """Main method for cleaning up network namespaces.

    This method will make two passes checking for namespaces to delete. The
    process will identify candidates, sleep, and call garbage collect. The
    garbage collection will re-verify that the namespace meets the criteria for
    deletion (ie it is empty). The period of sleep and the 2nd pass allow
    time for the namespace state to settle, so that the check prior deletion
    will re-confirm the namespace is empty.

    The utility is designed to clean-up after the forced or unexpected
    termination of Neutron agents.

    The --force flag should only be used as part of the cleanup of a devstack
    installation as it will blindly purge namespaces and their devices. This
    option also kills any lingering DHCP instances.
    """
    conf = setup_conf()
    conf()
    config.setup_logging()
    agent_config.setup_privsep()
    cleanup_network_namespaces(conf)
