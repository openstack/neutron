# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 New Dream Network, LLC (DreamHost)
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
#
# @author: Mark McClain, DreamHost
import os
import shutil
import socket

import netaddr

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import exceptions
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services.loadbalancer import constants as lb_const
from neutron.services.loadbalancer.drivers.haproxy import cfg as hacfg

LOG = logging.getLogger(__name__)
NS_PREFIX = 'qlbaas-'


class HaproxyNSDriver(object):
    def __init__(self, root_helper, state_path, vif_driver, vip_plug_callback):
        self.root_helper = root_helper
        self.state_path = state_path
        self.vif_driver = vif_driver
        self.vip_plug_callback = vip_plug_callback
        self.pool_to_port_id = {}

    def create(self, logical_config):
        pool_id = logical_config['pool']['id']
        namespace = get_ns_name(pool_id)

        self._plug(namespace, logical_config['vip']['port'])
        self._spawn(logical_config)

    def update(self, logical_config):
        pool_id = logical_config['pool']['id']
        pid_path = self._get_state_file_path(pool_id, 'pid')

        extra_args = ['-sf']
        extra_args.extend(p.strip() for p in open(pid_path, 'r'))
        self._spawn(logical_config, extra_args)

    def _spawn(self, logical_config, extra_cmd_args=()):
        pool_id = logical_config['pool']['id']
        namespace = get_ns_name(pool_id)
        conf_path = self._get_state_file_path(pool_id, 'conf')
        pid_path = self._get_state_file_path(pool_id, 'pid')
        sock_path = self._get_state_file_path(pool_id, 'sock')

        hacfg.save_config(conf_path, logical_config, sock_path)
        cmd = ['haproxy', '-f', conf_path, '-p', pid_path]
        cmd.extend(extra_cmd_args)

        ns = ip_lib.IPWrapper(self.root_helper, namespace)
        ns.netns.execute(cmd)

        # remember the pool<>port mapping
        self.pool_to_port_id[pool_id] = logical_config['vip']['port']['id']

    def destroy(self, pool_id):
        namespace = get_ns_name(pool_id)
        ns = ip_lib.IPWrapper(self.root_helper, namespace)
        pid_path = self._get_state_file_path(pool_id, 'pid')

        # kill the process
        kill_pids_in_file(self.root_helper, pid_path)

        # unplug the ports
        if pool_id in self.pool_to_port_id:
            self._unplug(namespace, self.pool_to_port_id[pool_id])

        # remove the configuration directory
        conf_dir = os.path.dirname(self._get_state_file_path(pool_id, ''))
        if os.path.isdir(conf_dir):
            shutil.rmtree(conf_dir)
        ns.garbage_collect_namespace()

    def exists(self, pool_id):
        namespace = get_ns_name(pool_id)
        root_ns = ip_lib.IPWrapper(self.root_helper)

        socket_path = self._get_state_file_path(pool_id, 'sock')
        if root_ns.netns.exists(namespace) and os.path.exists(socket_path):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(socket_path)
                return True
            except socket.error:
                pass
        return False

    def get_stats(self, pool_id):
        socket_path = self._get_state_file_path(pool_id, 'sock')
        TYPE_BACKEND_REQUEST = 2
        TYPE_SERVER_REQUEST = 4
        if os.path.exists(socket_path):
            parsed_stats = self._get_stats_from_socket(
                socket_path,
                entity_type=TYPE_BACKEND_REQUEST | TYPE_SERVER_REQUEST)
            pool_stats = self._get_backend_stats(parsed_stats)
            pool_stats['members'] = self._get_servers_stats(parsed_stats)
            return pool_stats
        else:
            LOG.warn(_('Stats socket not found for pool %s'), pool_id)
            return {}

    def _get_backend_stats(self, parsed_stats):
        TYPE_BACKEND_RESPONSE = '1'
        for stats in parsed_stats:
            if stats.get('type') == TYPE_BACKEND_RESPONSE:
                unified_stats = dict((k, stats.get(v, ''))
                                     for k, v in hacfg.STATS_MAP.items())
                return unified_stats

        return {}

    def _get_servers_stats(self, parsed_stats):
        TYPE_SERVER_RESPONSE = '2'
        res = {}
        for stats in parsed_stats:
            if stats.get('type') == TYPE_SERVER_RESPONSE:
                res[stats['svname']] = {
                    lb_const.STATS_STATUS: (constants.INACTIVE
                                            if stats['status'] == 'DOWN'
                                            else constants.ACTIVE),
                    lb_const.STATS_HEALTH: stats['check_status'],
                    lb_const.STATS_FAILED_CHECKS: stats['chkfail']
                }
        return res

    def _get_stats_from_socket(self, socket_path, entity_type):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(socket_path)
            s.send('show stat -1 %s -1\n' % entity_type)
            raw_stats = ''
            chunk_size = 1024
            while True:
                chunk = s.recv(chunk_size)
                raw_stats += chunk
                if len(chunk) < chunk_size:
                    break

            return self._parse_stats(raw_stats)
        except socket.error as e:
            LOG.warn(_('Error while connecting to stats socket: %s'), e)
            return {}

    def _parse_stats(self, raw_stats):
        stat_lines = raw_stats.splitlines()
        if len(stat_lines) < 2:
            return []
        stat_names = [name.strip('# ') for name in stat_lines[0].split(',')]
        res_stats = []
        for raw_values in stat_lines[1:]:
            if not raw_values:
                continue
            stat_values = [value.strip() for value in raw_values.split(',')]
            res_stats.append(dict(zip(stat_names, stat_values)))

        return res_stats

    def remove_orphans(self, known_pool_ids):
        raise NotImplementedError()

    def _get_state_file_path(self, pool_id, kind, ensure_state_dir=True):
        """Returns the file name for a given kind of config file."""
        confs_dir = os.path.abspath(os.path.normpath(self.state_path))
        conf_dir = os.path.join(confs_dir, pool_id)
        if ensure_state_dir:
            if not os.path.isdir(conf_dir):
                os.makedirs(conf_dir, 0o755)
        return os.path.join(conf_dir, kind)

    def _plug(self, namespace, port, reuse_existing=True):
        self.vip_plug_callback('plug', port)
        interface_name = self.vif_driver.get_device_name(Wrap(port))

        if ip_lib.device_exists(interface_name, self.root_helper, namespace):
            if not reuse_existing:
                raise exceptions.PreexistingDeviceFailure(
                    dev_name=interface_name
                )
        else:
            self.vif_driver.plug(
                port['network_id'],
                port['id'],
                interface_name,
                port['mac_address'],
                namespace=namespace
            )

        cidrs = [
            '%s/%s' % (ip['ip_address'],
                       netaddr.IPNetwork(ip['subnet']['cidr']).prefixlen)
            for ip in port['fixed_ips']
        ]
        self.vif_driver.init_l3(interface_name, cidrs, namespace=namespace)

        gw_ip = port['fixed_ips'][0]['subnet'].get('gateway_ip')
        if gw_ip:
            cmd = ['route', 'add', 'default', 'gw', gw_ip]
            ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                          namespace=namespace)
            ip_wrapper.netns.execute(cmd, check_exit_code=False)

    def _unplug(self, namespace, port_id):
        port_stub = {'id': port_id}
        self.vip_plug_callback('unplug', port_stub)
        interface_name = self.vif_driver.get_device_name(Wrap(port_stub))
        self.vif_driver.unplug(interface_name, namespace=namespace)


# NOTE (markmcclain) For compliance with interface.py which expects objects
class Wrap(object):
    """A light attribute wrapper for compatibility with the interface lib."""
    def __init__(self, d):
        self.__dict__.update(d)

    def __getitem__(self, key):
        return self.__dict__[key]


def get_ns_name(namespace_id):
    return NS_PREFIX + namespace_id


def kill_pids_in_file(root_helper, pid_path):
    if os.path.exists(pid_path):
        with open(pid_path, 'r') as pids:
            for pid in pids:
                pid = pid.strip()
                try:
                    utils.execute(['kill', '-9', pid], root_helper)
                except RuntimeError:
                    LOG.exception(
                        _('Unable to kill haproxy process: %s'),
                        pid
                    )
