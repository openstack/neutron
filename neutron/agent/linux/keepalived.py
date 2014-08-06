# Copyright (C) 2014 eNovance SAS <licensing@enovance.com>
#
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

import itertools
import os
import stat

from oslo.config import cfg

from neutron.agent.linux import external_process
from neutron.agent.linux import utils
from neutron.common import exceptions
from neutron.openstack.common.gettextutils import _LW
from neutron.openstack.common import log as logging

VALID_STATES = ['MASTER', 'BACKUP']
VALID_NOTIFY_STATES = ['master', 'backup', 'fault']
VALID_AUTH_TYPES = ['AH', 'PASS']
HA_DEFAULT_PRIORITY = 50

LOG = logging.getLogger(__name__)


class InvalidInstanceStateException(exceptions.NeutronException):
    message = (_('Invalid instance state: %%(state)s, valid states are: '
                 '%(valid_states)s') %
               {'valid_states': ', '.join(VALID_STATES)})


class InvalidNotifyStateException(exceptions.NeutronException):
    message = (_('Invalid notify state: %%(state)s, valid states are: '
                 '%(valid_notify_states)s') %
               {'valid_notify_states': ', '.join(VALID_NOTIFY_STATES)})


class InvalidAuthenticationTypeExecption(exceptions.NeutronException):
    message = (_('Invalid authentication type: %%(auth_type)s, '
                 'valid types are: %(valid_auth_types)s') %
               {'valid_auth_types': ', '.join(VALID_AUTH_TYPES)})


class KeepalivedVipAddress(object):
    """A virtual address entry of a keepalived configuration."""

    def __init__(self, ip_address, interface_name):
        self.ip_address = ip_address
        self.interface_name = interface_name

    def build_config(self):
        return '%s dev %s' % (self.ip_address, self.interface_name)


class KeepalivedVirtualRoute(object):
    """A virtual route entry of a keepalived configuration."""

    def __init__(self, destination, nexthop, interface_name=None):
        self.destination = destination
        self.nexthop = nexthop
        self.interface_name = interface_name

    def build_config(self):
        output = '%s via %s' % (self.destination, self.nexthop)
        if self.interface_name:
            output += ' dev %s' % self.interface_name
        return output


class KeepalivedGroup(object):
    """Group section of a keepalived configuration."""

    def __init__(self, ha_vr_id):
        self.ha_vr_id = ha_vr_id
        self.name = 'VG_%s' % ha_vr_id
        self.instance_names = set()
        self.notifiers = []

    def add_instance(self, instance):
        self.instance_names.add(instance.name)

    def set_notify(self, state, path):
        if state not in VALID_NOTIFY_STATES:
            raise InvalidNotifyStateException(state=state)
        self.notifiers.append((state, path))

    def build_config(self):
        return itertools.chain(['vrrp_sync_group %s {' % self.name,
                                '    group {'],
                               ('        %s' % i for i in self.instance_names),
                               ['    }'],
                               ('    notify_%s "%s"' % (state, path)
                                for state, path in self.notifiers),
                               ['}'])


class KeepalivedInstance(object):
    """Instance section of a keepalived configuration."""

    def __init__(self, state, interface, vrouter_id,
                 priority=HA_DEFAULT_PRIORITY, advert_int=None,
                 mcast_src_ip=None, nopreempt=False):
        self.name = 'VR_%s' % vrouter_id

        if state not in VALID_STATES:
            raise InvalidInstanceStateException(state=state)

        self.state = state
        self.interface = interface
        self.vrouter_id = vrouter_id
        self.priority = priority
        self.nopreempt = nopreempt
        self.advert_int = advert_int
        self.mcast_src_ip = mcast_src_ip
        self.track_interfaces = []
        self.vips = []
        self.virtual_routes = []
        self.authentication = tuple()

    def set_authentication(self, auth_type, password):
        if auth_type not in VALID_AUTH_TYPES:
            raise InvalidAuthenticationTypeExecption(auth_type=auth_type)

        self.authentication = (auth_type, password)

    def add_vip(self, ip_cidr, interface_name):
        self.vips.append(KeepalivedVipAddress(ip_cidr, interface_name))

    def remove_vips_vroutes_by_interface(self, interface_name):
        self.vips = [vip for vip in self.vips
                     if vip.interface_name != interface_name]

        self.virtual_routes = [vroute for vroute in self.virtual_routes
                               if vroute.interface_name != interface_name]

    def remove_vip_by_ip_address(self, ip_address):
        self.vips = [vip for vip in self.vips
                     if vip.ip_address != ip_address]

    def _build_track_interface_config(self):
        return itertools.chain(
            ['    track_interface {'],
            ('        %s' % i for i in self.track_interfaces),
            ['    }'])

    def _build_vips_config(self):
        vips_sorted = sorted(self.vips, key=lambda vip: vip.ip_address)
        first_address = vips_sorted.pop(0)

        vips_result = ['    virtual_ipaddress {',
                       '        %s' % first_address.build_config(),
                       '    }']
        if vips_sorted:
            vips_result.extend(
                itertools.chain(['    virtual_ipaddress_excluded {'],
                                ('        %s' % vip.build_config()
                                 for vip in vips_sorted),
                                ['    }']))

        return vips_result

    def _build_virtual_routes_config(self):
        return itertools.chain(['    virtual_routes {'],
                               ('        %s' % route.build_config()
                                for route in self.virtual_routes),
                               ['    }'])

    def build_config(self):
        config = ['vrrp_instance %s {' % self.name,
                  '    state %s' % self.state,
                  '    interface %s' % self.interface,
                  '    virtual_router_id %s' % self.vrouter_id,
                  '    priority %s' % self.priority]

        if self.nopreempt:
            config.append('    nopreempt')

        if self.advert_int:
            config.append('    advert_int %s' % self.advert_int)

        if self.authentication:
            auth_type, password = self.authentication
            authentication = ['    authentication {',
                              '        auth_type %s' % auth_type,
                              '        auth_pass %s' % password,
                              '    }']
            config.extend(authentication)

        if self.mcast_src_ip:
            config.append('    mcast_src_ip %s' % self.mcast_src_ip)

        if self.track_interfaces:
            config.extend(self._build_track_interface_config())

        if self.vips:
            config.extend(self._build_vips_config())

        if self.virtual_routes:
            config.extend(self._build_virtual_routes_config())

        config.append('}')

        return config


class KeepalivedConf(object):
    """A keepalived configuration."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.groups = {}
        self.instances = {}

    def add_group(self, group):
        self.groups[group.ha_vr_id] = group

    def get_group(self, ha_vr_id):
        return self.groups.get(ha_vr_id)

    def add_instance(self, instance):
        self.instances[instance.vrouter_id] = instance

    def get_instance(self, vrouter_id):
        return self.instances.get(vrouter_id)

    def build_config(self):
        config = []

        for group in self.groups.values():
            config.extend(group.build_config())

        for instance in self.instances.values():
            config.extend(instance.build_config())

        return config

    def get_config_str(self):
        """Generates and returns the keepalived configuration.

        :return: Keepalived configuration string.
        """
        return '\n'.join(self.build_config())


class KeepalivedNotifierMixin(object):
    def _get_notifier_path(self, state):
        return self._get_full_config_file_path('notify_%s.sh' % state)

    def _write_notify_script(self, state, script):
        name = self._get_notifier_path(state)
        utils.replace_file(name, script)
        st = os.stat(name)
        os.chmod(name, st.st_mode | stat.S_IEXEC)

        return name

    def _prepend_shebang(self, script):
        return '#!/usr/bin/env bash\n%s' % script

    def _append_state(self, script, state):
        state_path = self._get_full_config_file_path('state')
        return '%s\necho -n %s > %s' % (script, state, state_path)

    def add_notifier(self, script, state, ha_vr_id):
        """Add a master, backup or fault notifier.

        These notifiers are executed when keepalived invokes a state
        transition. Write a notifier to disk and add it to the
        configuration.
        """

        script_with_prefix = self._prepend_shebang(' '.join(script))
        full_script = self._append_state(script_with_prefix, state)
        self._write_notify_script(state, full_script)

        group = self.config.get_group(ha_vr_id)
        group.set_notify(state, self._get_notifier_path(state))

    def get_conf_dir(self):
        confs_dir = os.path.abspath(os.path.normpath(self.conf_path))
        conf_dir = os.path.join(confs_dir, self.resource_id)
        return conf_dir

    def _get_full_config_file_path(self, filename, ensure_conf_dir=True):
        conf_dir = self.get_conf_dir()
        if ensure_conf_dir and not os.path.isdir(conf_dir):
            os.makedirs(conf_dir, 0o755)
        return os.path.join(conf_dir, filename)


class KeepalivedManager(KeepalivedNotifierMixin):
    """Wrapper for keepalived.

    This wrapper permits to write keepalived config files, to start/restart
    keepalived process.

    """

    def __init__(self, resource_id, config, conf_path='/tmp',
                 namespace=None, root_helper=None):
        self.resource_id = resource_id
        self.config = config
        self.namespace = namespace
        self.root_helper = root_helper
        self.conf_path = conf_path
        self.conf = cfg.CONF
        self.process = None
        self.spawned = False

    def _output_config_file(self):
        config_str = self.config.get_config_str()
        config_path = self._get_full_config_file_path('keepalived.conf')
        utils.replace_file(config_path, config_str)

        return config_path

    def spawn(self):
        config_path = self._output_config_file()

        self.process = external_process.ProcessManager(
            self.conf,
            self.resource_id,
            self.root_helper,
            self.namespace,
            pids_path=self.conf_path)

        def callback(pid_file):
            cmd = ['keepalived', '-P',
                   '-f', config_path,
                   '-p', pid_file,
                   '-r', '%s-vrrp' % pid_file]
            return cmd

        self.process.enable(callback)

        self.spawned = True
        LOG.debug('Keepalived spawned with config %s', config_path)

    def spawn_or_restart(self):
        if self.process:
            self.restart()
        else:
            self.spawn()

    def restart(self):
        if self.process.active:
            self._output_config_file()
            self.process.reload_cfg()
        else:
            LOG.warn(_LW('A previous instance of keepalived seems to be dead, '
                         'unable to restart it, a new instance will be '
                         'spawned'))
            self.process.disable()
            self.spawn()

    def disable(self):
        if self.process:
            self.process.disable(sig='15')
            self.spawned = False

    def revive(self):
        if self.spawned and not self.process.active:
            self.restart()
