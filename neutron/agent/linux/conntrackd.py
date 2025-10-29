# Copyright (c) 2015 UnitedStack, Inc.
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

import os
import signal

import jinja2

from neutron_lib.utils import file as file_utils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils.fileutils import ensure_tree

from neutron._i18n import _
from neutron.agent.linux import external_process
from neutron.agent.linux import utils
from neutron.common import utils as common_utils

CONNTRACKD_SERVICE_NAME = 'conntrackd'
SIGTERM_TIMEOUT = 5

# Unix socket path length is limited to 107 characters in the
# conntrackd source code. See UNIX_PATH_MAX constant in include/local.h
UNIX_PATH_MAX = 107

LOG = logging.getLogger(__name__)


CONFIG_TEMPLATE = jinja2.Template(
    """
General {
    HashSize {{ hash_size }}
    HashLimit {{ hash_limit }}
    Syslog on
    LockFile {{ lockfile_path }}
    UNIX {
        Path {{ socket_path }}
        Backlog {{ unix_backlog }}
    }
    SocketBufferSize {{ socket_buffer_size }}
    SocketBufferSizeMaxGrown {{ socket_buffer_size_max_grown }}
    Filter From Kernelspace {
        Protocol Accept {
{%- for proto in protocol_accept %}
            {{ proto }}
{%- endfor %}
        }
        Address Ignore {
{%- for version, addr in address_ignore %}
            IPv{{ version }}_address {{ addr }}
{%- endfor %}
        }
    }
}
Sync {
    Mode FTFW {
    }
    Multicast Default {
        IPv4_address {{ ipv4_mcast_addr }}
        IPv4_interface {{ ipv4_interface }}
        Group {{ mcast_group }}
        Interface {{ interface }}
        SndSocketBuffer {{ snd_socket_buffer }}
        RcvSocketBuffer {{ rcv_socket_buffer }}
        Checksum on
    }
}
""")


class ConntrackdManager:
    """Wrapper for conntrackd.

    This wrapper permits to write conntrackd config file,
    to start/restart conntrackd process.

    """

    def __init__(self, resource_id, process_monitor, agent_conf,
                 mcast_iface_addr, ha_vr_id, ha_iface, namespace=None):
        self.resource_id = resource_id
        self.process_monitor = process_monitor
        self.agent_conf = agent_conf
        self.mcast_iface_addr = mcast_iface_addr
        self.ha_vr_id = ha_vr_id
        self.ha_iface = ha_iface
        self.namespace = namespace

    def get_full_config_file_path(self, filename, maxlen=255):
        # Maximum PATH length for most paths in conntrackd is limited to
        # 255 characters.
        conf_dir = self.get_conf_dir()
        ensure_tree(conf_dir, 0o755)
        path = os.path.join(conf_dir, filename)

        if len(path) > maxlen:
            raise ValueError(_('Configuration file path "%(path)s" exceeds '
                               'maximum length of %(maxlen)i characters.') %
                             {'path': path,
                              'maxlen': maxlen})

        return path

    def get_conf_dir(self):
        confs_dir = os.path.abspath(
            os.path.normpath(self.agent_conf.ha_confs_path))

        return os.path.join(confs_dir, self.resource_id)

    def get_pid_file_path(self):
        return self.get_full_config_file_path('conntrackd.pid')

    def get_lockfile_path(self):
        return self.get_full_config_file_path('conntrackd.lock')

    def get_ctlfile_path(self):
        return self.get_full_config_file_path(
            'conntrackd.ctl',
            maxlen=UNIX_PATH_MAX,
        )

    def get_conffile_path(self):
        return self.get_full_config_file_path('conntrackd.conf')

    def create_pid_file(self):
        config_path = self.get_conffile_path()
        pid_file = self.get_pid_file_path()

        cmd = 'conntrackd -d -C %s' % config_path
        pid = utils.pgrep(cmd)

        if not pid:
            raise RuntimeError(_('No process for "%s" found.') % cmd)

        file_utils.replace_file(pid_file, pid)

    def spawn(self):
        config_path = self.output_config_file()

        def callback(pidfile):
            cmd = ['conntrackd', '-d',
                   '-C', config_path]
            return cmd

        def pre_cmd_callback():
            # conntrackd.lock and conntrackd.ctl must be removed before
            # starting a new conntrackd.
            utils.delete_if_exists(self.get_lockfile_path(), run_as_root=True)
            utils.delete_if_exists(self.get_ctlfile_path(), run_as_root=True)

        def post_cmd_callback():
            self.create_pid_file()

            # Synchronize connection tracking state with peer
            cmd = ['conntrackd', '-C', config_path, '-n']
            utils.execute(cmd, run_as_root=True, check_exit_code=True)

        pm = self.get_process(callback=callback,
                              pre_cmd_callback=pre_cmd_callback,
                              post_cmd_callback=post_cmd_callback)
        pm.enable(reload_cfg=False)

        self.process_monitor.register(uuid=self.resource_id,
                                      service_name=CONNTRACKD_SERVICE_NAME,
                                      monitored_process=pm)

        LOG.debug('Conntrackd spawned with config %s', config_path)

    def get_process(self, callback=None, pre_cmd_callback=None,
                    post_cmd_callback=None):
        return external_process.ProcessManager(
            cfg.CONF,
            self.resource_id,
            self.namespace,
            default_cmd_callback=callback,
            default_pre_cmd_callback=pre_cmd_callback,
            default_post_cmd_callback=post_cmd_callback,
            pid_file=self.get_pid_file_path())

    def disable(self):
        self.process_monitor.unregister(uuid=self.resource_id,
                                        service_name=CONNTRACKD_SERVICE_NAME)

        pm = self.get_process()
        if not pm.active:
            return

        # First try to stop conntrackd by using its own control command
        config_path = self.get_conffile_path()
        cmd = ['conntrackd', '-C', config_path, '-k']
        utils.execute(cmd, run_as_root=True)

        try:
            common_utils.wait_until_true(lambda: not pm.active,
                                         timeout=SIGTERM_TIMEOUT)
        except common_utils.WaitTimeout:
            LOG.warning('Conntrackd process %s did not finish after asking it '
                        'to shut down in %s seconds, sending SIGKILL signal.',
                        pm.pid, SIGTERM_TIMEOUT)
            pm.disable(sig=str(int(signal.SIGKILL)))

    def build_config(self):
        return CONFIG_TEMPLATE.render(
            hash_size=self.agent_conf.ha_conntrackd_hashsize,
            hash_limit=self.agent_conf.ha_conntrackd_hashlimit,
            lockfile_path=self.get_lockfile_path(),
            socket_path=self.get_ctlfile_path(),
            unix_backlog=self.agent_conf.ha_conntrackd_unix_backlog,
            socket_buffer_size=self.agent_conf.ha_conntrackd_socketbuffersize,
            socket_buffer_size_max_grown=(
                self.agent_conf.ha_conntrackd_socketbuffersize_max_grown
            ),
            protocol_accept=[
                'TCP', 'SCTP', 'DCCP', 'UDP', 'ICMP', 'IPv6-ICMP'
            ],
            # Ignore loopback and HA sync addresses
            address_ignore=[
                (4, '127.0.0.1'),
                (6, '::1'),
                (4, self.mcast_iface_addr),
            ],
            ipv4_mcast_addr=self.agent_conf.ha_conntrackd_ipv4_mcast_addr,
            ipv4_interface=self.mcast_iface_addr,
            mcast_group=self.agent_conf.ha_conntrackd_group + self.ha_vr_id,
            interface=self.ha_iface,
            snd_socket_buffer=self.agent_conf.ha_conntrackd_sndsocketbuffer,
            rcv_socket_buffer=self.agent_conf.ha_conntrackd_rcvsocketbuffer,
        )

    def output_config_file(self):
        config_path = self.get_conffile_path()
        file_utils.replace_file(config_path, self.build_config())

        return config_path
