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

import errno
import itertools
import os
import signal

import netaddr
from neutron_lib import constants
from neutron_lib import exceptions
from neutron_lib.utils import file as file_utils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import fileutils

from neutron._i18n import _
from neutron.agent.linux import external_process
from neutron.cmd import runtime_checks as checks
from neutron.common import utils

VALID_STATES = ['MASTER', 'BACKUP']
VALID_AUTH_TYPES = ['AH', 'PASS']
HA_DEFAULT_PRIORITY = 50
PRIMARY_VIP_RANGE_SIZE = 24
KEEPALIVED_SERVICE_NAME = 'keepalived'
KEEPALIVED_EMAIL_FROM = 'neutron@openstack.local'
KEEPALIVED_ROUTER_ID = 'neutron'
GARP_PRIMARY_DELAY = 60
HEALTH_CHECK_NAME = 'ha_health_check'
_IS_NO_TRACK_SUPPORTED = None

LOG = logging.getLogger(__name__)
SIGTERM_TIMEOUT = 5


def _is_keepalived_use_no_track_supported():
    global _IS_NO_TRACK_SUPPORTED
    if _IS_NO_TRACK_SUPPORTED is None:
        _IS_NO_TRACK_SUPPORTED = (
            checks.keepalived_use_no_track_support())
    return _IS_NO_TRACK_SUPPORTED


def get_free_range(parent_range, excluded_ranges, size=PRIMARY_VIP_RANGE_SIZE):
    """Get a free IP range, from parent_range, of the specified size.

    :param parent_range: String representing an IP range. E.g: '169.254.0.0/16'
    :param excluded_ranges: A list of strings to be excluded from parent_range
    :param size: What should be the size of the range returned?
    :return: A string representing an IP range
    """
    free_cidrs = netaddr.IPSet([parent_range]) - netaddr.IPSet(excluded_ranges)
    for cidr in free_cidrs.iter_cidrs():
        if cidr.prefixlen <= size:
            return '%s/%s' % (cidr.network, size)

    raise ValueError(_('Network of size %(size)s, from IP range '
                       '%(parent_range)s excluding IP ranges '
                       '%(excluded_ranges)s was not found.') %
                     {'size': size,
                      'parent_range': parent_range,
                      'excluded_ranges': excluded_ranges})


class InvalidInstanceStateException(exceptions.NeutronException):
    message = _('Invalid instance state: %(state)s, valid states are: '
                '%(valid_states)s')

    def __init__(self, **kwargs):
        if 'valid_states' not in kwargs:
            kwargs['valid_states'] = ', '.join(VALID_STATES)
        super(InvalidInstanceStateException, self).__init__(**kwargs)


class InvalidAuthenticationTypeException(exceptions.NeutronException):
    message = _('Invalid authentication type: %(auth_type)s, '
                'valid types are: %(valid_auth_types)s')

    def __init__(self, **kwargs):
        if 'valid_auth_types' not in kwargs:
            kwargs['valid_auth_types'] = ', '.join(VALID_AUTH_TYPES)
        super(InvalidAuthenticationTypeException, self).__init__(**kwargs)


class KeepalivedVipAddress(object):
    """A virtual address entry of a keepalived configuration."""

    def __init__(self, ip_address, interface_name, scope=None, track=True):
        self.ip_address = ip_address
        self.interface_name = interface_name
        self.scope = scope
        self.track = track

    def __eq__(self, other):
        return (isinstance(other, KeepalivedVipAddress) and
                self.ip_address == other.ip_address)

    def __str__(self):
        return '[%s, %s, %s, %s]' % (self.ip_address,
                                     self.interface_name,
                                     self.scope,
                                     self.track)

    def build_config(self):
        result = '%s dev %s' % (self.ip_address, self.interface_name)
        if self.scope:
            result += ' scope %s' % self.scope
        if cfg.CONF.keepalived_use_no_track and not self.track:
            if _is_keepalived_use_no_track_supported():
                result += ' no_track'
            else:
                LOG.warning("keepalived_use_no_track cfg option is True but "
                            "keepalived on host seems to not support this "
                            "option")
        return result


class KeepalivedVirtualRoute(object):
    """A virtual route entry of a keepalived configuration."""

    def __init__(self, destination, nexthop, interface_name=None,
                 scope=None):
        self.destination = destination
        self.nexthop = nexthop
        self.interface_name = interface_name
        self.scope = scope

    def build_config(self):
        output = self.destination
        if self.nexthop:
            output += ' via %s' % self.nexthop
        if self.interface_name:
            output += ' dev %s' % self.interface_name
        if self.scope:
            output += ' scope %s' % self.scope
        if cfg.CONF.keepalived_use_no_track:
            if _is_keepalived_use_no_track_supported():
                output += ' no_track'
            else:
                LOG.warning("keepalived_use_no_track cfg option is True but "
                            "keepalived on host seems to not support this "
                            "option")
        return output


class KeepalivedInstanceRoutes(object):
    def __init__(self):
        self.gateway_routes = []
        self.extra_routes = []
        self.extra_subnets = []

    def remove_routes_on_interface(self, interface_name):
        self.gateway_routes = [gw_rt for gw_rt in self.gateway_routes
                               if gw_rt.interface_name != interface_name]
        # NOTE(amuller): extra_routes are initialized from the router's
        # 'routes' attribute. These routes do not have an interface
        # parameter and so cannot be removed via an interface_name lookup.
        self.extra_subnets = [route for route in self.extra_subnets if
                              route.interface_name != interface_name]

    @property
    def routes(self):
        return self.gateway_routes + self.extra_routes + self.extra_subnets

    def __len__(self):
        return len(self.routes)

    def build_config(self):
        return itertools.chain(['    virtual_routes {'],
                               ('        %s' % route.build_config()
                                for route in self.routes),
                               ['    }'])


class KeepalivedInstance(object):
    """Instance section of a keepalived configuration."""

    def __init__(self, state, interface, vrouter_id, ha_cidrs,
                 priority=HA_DEFAULT_PRIORITY, advert_int=None,
                 mcast_src_ip=None, nopreempt=False,
                 garp_primary_delay=GARP_PRIMARY_DELAY,
                 vrrp_health_check_interval=0,
                 ha_conf_dir=None):
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
        self.garp_primary_delay = garp_primary_delay
        self.track_interfaces = []
        self.vips = []
        self.virtual_routes = KeepalivedInstanceRoutes()
        self.authentication = None
        self.track_script = None
        self.primary_vip_range = get_free_range(
            parent_range=constants.PRIVATE_CIDR_RANGE,
            excluded_ranges=[constants.METADATA_CIDR,
                             constants.DVR_FIP_LL_CIDR] + ha_cidrs,
            size=PRIMARY_VIP_RANGE_SIZE)

        if vrrp_health_check_interval > 0:
            self.track_script = KeepalivedTrackScript(
                vrrp_health_check_interval, ha_conf_dir, self.vrouter_id)

    def set_authentication(self, auth_type, password):
        if auth_type not in VALID_AUTH_TYPES:
            raise InvalidAuthenticationTypeException(auth_type=auth_type)

        self.authentication = (auth_type, password)

    def add_vip(self, ip_cidr, interface_name, scope):
        track = interface_name in self.track_interfaces
        vip = KeepalivedVipAddress(ip_cidr, interface_name, scope, track=track)
        if vip not in self.vips:
            self.vips.append(vip)
        else:
            LOG.debug('VIP %s already present in %s', vip, self.vips)

    def remove_vips_vroutes_by_interface(self, interface_name):
        self.vips = [vip for vip in self.vips
                     if vip.interface_name != interface_name]

        self.virtual_routes.remove_routes_on_interface(interface_name)

    def remove_vip_by_ip_address(self, ip_address):
        self.vips = [vip for vip in self.vips
                     if vip.ip_address != ip_address]

    def get_existing_vip_ip_addresses(self, interface_name):
        return [vip.ip_address for vip in self.vips
                if vip.interface_name == interface_name]

    def _build_track_interface_config(self):
        return itertools.chain(
            ['    track_interface {'],
            ('        %s' % i for i in self.track_interfaces),
            ['    }'])

    def get_primary_vip(self):
        """Return an address in the primary_vip_range CIDR, with the router's
        VRID in the host section.

        For example, if primary_vip_range is 169.254.0.0/24, and this router's
        VRID is 5, the result is 169.254.0.5. Using the VRID assures that
        the primary VIP is consistent amongst HA router instances on different
        nodes.
        """

        ip = (netaddr.IPNetwork(self.primary_vip_range).network +
              self.vrouter_id)
        return str(netaddr.IPNetwork('%s/%s' % (ip, PRIMARY_VIP_RANGE_SIZE)))

    def _build_vips_config(self):
        # NOTE(amuller): The primary VIP must be consistent in order to avoid
        # keepalived bugs. Changing the VIP in the 'virtual_ipaddress' and
        # SIGHUP'ing keepalived can remove virtual routers, including the
        # router's default gateway.
        # We solve this by never changing the VIP in the virtual_ipaddress
        # section, herein known as the primary VIP.
        # The only interface known to exist for HA routers is the HA interface
        # (self.interface). We generate an IP on that device and use it as the
        # primary VIP. The other VIPs (Internal interfaces IPs, the external
        # interface IP and floating IPs) are placed in the
        # virtual_ipaddress_excluded section.

        primary = KeepalivedVipAddress(self.get_primary_vip(), self.interface)
        vips_result = ['    virtual_ipaddress {',
                       '        %s' % primary.build_config(),
                       '    }']

        if self.vips:
            vips_result.extend(
                itertools.chain(['    virtual_ipaddress_excluded {'],
                                ('        %s' % vip.build_config()
                                 for vip in
                                 sorted(self.vips,
                                        key=lambda vip: vip.ip_address)),
                                ['    }']))

        return vips_result

    def _build_virtual_routes_config(self):
        return itertools.chain(['    virtual_routes {'],
                               ('        %s' % route.build_config()
                                for route in self.virtual_routes),
                               ['    }'])

    def build_config(self):
        if self.track_script:
            config = self.track_script.build_config_preamble()
            self.track_script.routes = self.virtual_routes.gateway_routes
            self.track_script.vips = self.vips
        else:
            config = []

        config.extend(['vrrp_instance %s {' % self.name,
                       '    state %s' % self.state,
                       '    interface %s' % self.interface,
                       '    virtual_router_id %s' % self.vrouter_id,
                       '    priority %s' % self.priority,
                       '    garp_master_delay %s' % self.garp_primary_delay])

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

        config.extend(self._build_vips_config())

        if len(self.virtual_routes):
            config.extend(self.virtual_routes.build_config())

        if self.track_script:
            config.extend(self.track_script.build_config())

        config.append('}')

        return config


class KeepalivedConf(object):
    """A keepalived configuration."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.instances = {}

    def add_instance(self, instance):
        self.instances[instance.vrouter_id] = instance

    def get_instance(self, vrouter_id):
        return self.instances.get(vrouter_id)

    def build_config(self):
        config = ['global_defs {',
                  '    notification_email_from %s' % KEEPALIVED_EMAIL_FROM,
                  '    router_id %s' % KEEPALIVED_ROUTER_ID,
                  '}'
                  ]

        for instance in self.instances.values():
            config.extend(instance.build_config())

        return config

    def get_config_str(self):
        """Generates and returns the keepalived configuration.

        :return: Keepalived configuration string.
        """
        return '\n'.join(self.build_config())


class KeepalivedManager(object):
    """Wrapper for keepalived.

    This wrapper permits to write keepalived config files, to start/restart
    keepalived process.

    """

    def __init__(self, resource_id, config, process_monitor, conf_path,
                 namespace=None, throttle_restart_value=None):
        self.resource_id = resource_id
        self.config = config
        self.namespace = namespace
        self.process_monitor = process_monitor
        self.conf_path = conf_path
        # configure throttler for spawn to introduce delay between SIGHUPs,
        # otherwise keepalived primary may unnecessarily flip to backup
        if throttle_restart_value is not None:
            self._throttle_spawn(throttle_restart_value)

    # pylint: disable=method-hidden
    def _throttle_spawn(self, threshold):
        self.spawn = utils.throttler(threshold)(self.spawn)

    def get_conf_dir(self):
        confs_dir = os.path.abspath(os.path.normpath(self.conf_path))
        conf_dir = os.path.join(confs_dir, self.resource_id)
        return conf_dir

    def get_full_config_file_path(self, filename, ensure_conf_dir=True):
        conf_dir = self.get_conf_dir()
        if ensure_conf_dir:
            fileutils.ensure_tree(conf_dir, mode=0o755)
        return os.path.join(conf_dir, filename)

    def _output_config_file(self):
        config_str = self.config.get_config_str()
        LOG.debug("Router %s keepalived config: %s",
                  self.resource_id, config_str)
        config_path = self.get_full_config_file_path('keepalived.conf')
        file_utils.replace_file(config_path, config_str)

        return config_path

    @staticmethod
    def _safe_remove_pid_file(pid_file):
        try:
            os.remove(pid_file)
        except OSError as e:
            if e.errno != errno.ENOENT:
                LOG.error("Could not delete file %s, keepalived can "
                          "refuse to start.", pid_file)

    def get_vrrp_pid_file_name(self, base_pid_file):
        return '%s-vrrp' % base_pid_file

    def get_conf_on_disk(self):
        config_path = self.get_full_config_file_path('keepalived.conf')
        try:
            with open(config_path) as conf:
                return conf.read()
        except (OSError, IOError) as e:
            if e.errno != errno.ENOENT:
                raise

    def spawn(self):
        config_path = self._output_config_file()

        for key, instance in self.config.instances.items():
            if instance.track_script:
                instance.track_script.write_check_script()

        keepalived_pm = self.get_process()
        vrrp_pm = self._get_vrrp_process(
            self.get_vrrp_pid_file_name(keepalived_pm.get_pid_file_name()))

        keepalived_pm.default_cmd_callback = (
            self._get_keepalived_process_callback(vrrp_pm, config_path))

        keepalived_pm.enable(reload_cfg=True)

        self.process_monitor.register(uuid=self.resource_id,
                                      service_name=KEEPALIVED_SERVICE_NAME,
                                      monitored_process=keepalived_pm)

        LOG.debug('Keepalived spawned with config %s', config_path)

    def disable(self):
        self.process_monitor.unregister(uuid=self.resource_id,
                                        service_name=KEEPALIVED_SERVICE_NAME)

        pm = self.get_process()
        pm.disable(sig=str(int(signal.SIGTERM)))
        try:
            utils.wait_until_true(lambda: not pm.active,
                                  timeout=SIGTERM_TIMEOUT)
        except utils.WaitTimeout:
            LOG.warning('Keepalived process %s did not finish after SIGTERM '
                        'signal in %s seconds, sending SIGKILL signal',
                        pm.pid, SIGTERM_TIMEOUT)
            pm.disable(sig=str(int(signal.SIGKILL)))

    def check_processes(self):
        keepalived_pm = self.get_process()
        vrrp_pm = self._get_vrrp_process(
            self.get_vrrp_pid_file_name(keepalived_pm.get_pid_file_name()))
        return keepalived_pm.active and vrrp_pm.active

    def get_process(self):
        return external_process.ProcessManager(
            cfg.CONF,
            self.resource_id,
            self.namespace,
            service=KEEPALIVED_SERVICE_NAME,
            pids_path=self.conf_path)

    def _get_vrrp_process(self, pid_file):
        return external_process.ProcessManager(
            cfg.CONF,
            self.resource_id,
            self.namespace,
            pid_file=pid_file)

    def _get_keepalived_process_callback(self, vrrp_pm, config_path):

        def callback(pid_file):
            # If keepalived process crashed unexpectedly, the vrrp process
            # will be orphan and prevent keepalived process to be spawned.
            # A check here will let the l3-agent to kill the orphan process
            # and spawn keepalived successfully.
            if vrrp_pm.active:
                vrrp_pm.disable()

            self._safe_remove_pid_file(pid_file)
            self._safe_remove_pid_file(self.get_vrrp_pid_file_name(pid_file))

            cmd = ['keepalived', '-P',
                   '-f', config_path,
                   '-p', pid_file,
                   '-r', self.get_vrrp_pid_file_name(pid_file)]
            if logging.is_debug_enabled(cfg.CONF):
                cmd.append('-D')
            return cmd

        return callback


class KeepalivedTrackScript(KeepalivedConf):
    """Track script generator for Keepalived"""

    def __init__(self, interval, conf_dir, vr_id):
        self.interval = interval
        self.conf_dir = conf_dir
        self.vr_id = vr_id
        self.routes = []
        self.vips = []

    def build_config_preamble(self):
        config = ['',
                  'vrrp_script %s_%s {' % (HEALTH_CHECK_NAME, self.vr_id),
                  '    script "%s"' % self._get_script_location(),
                  '    interval %s' % self.interval,
                  '    fall 2',
                  '    rise 2',
                  '}',
                  '']

        return config

    def _is_needed(self):
        """Check if track script is needed by checking amount of routes.

        :return: True/False
        """
        return len(self.routes) > 0

    def build_config(self):
        if not self._is_needed():
            return ''

        config = ['    track_script {',
                  '        %s_%s' % (HEALTH_CHECK_NAME, self.vr_id),
                  '    }']

        return config

    def build_script(self):
        return itertools.chain(['#!/bin/bash -eu'],
                               ['%s' % self._check_ip_assigned()],
                               ('%s' % self._add_ip_addr(route.nexthop)
                                for route in self.routes if route.nexthop),
                               )

    def _add_ip_addr(self, ip_addr):
        cmd = {
            4: 'ping',
            6: 'ping6',
        }.get(netaddr.IPAddress(ip_addr).version)

        return '%s -c 1 -w 1 %s 1>/dev/null || exit 1' % (cmd, ip_addr)

    def _check_ip_assigned(self):
        cmd = 'ip a | grep %s || exit 0'
        return cmd % netaddr.IPNetwork(self.vips[0].ip_address).ip if len(
            self.vips) else ''

    def _get_script_str(self):
        """Generates and returns bash script to verify connectivity.

        :return: Bash script code
        """
        return '\n'.join(self.build_script())

    def _get_script_location(self):
        return os.path.join(self.conf_dir,
                            'ha_check_script_%s.sh' % self.vr_id)

    def write_check_script(self):
        if not self._is_needed():
            return

        file_utils.replace_file(
            self._get_script_location(), self._get_script_str(), 0o520)
