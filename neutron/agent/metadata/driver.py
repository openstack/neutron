# Copyright 2014 OpenStack Foundation.
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

import grp
import os
import pwd
import signal

from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from neutron_lib import constants
from neutron_lib import exceptions
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import netutils

from neutron._i18n import _
from neutron.agent.l3 import ha_router
from neutron.agent.l3 import namespaces
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils
from neutron.common import _constants as common_constants
from neutron.common import coordination
from neutron.common import metadata as comm_meta
from neutron.common import utils as common_utils


LOG = logging.getLogger(__name__)

SIGTERM_TIMEOUT = 5

METADATA_SERVICE_NAME = 'metadata-proxy'
HAPROXY_SERVICE = 'haproxy'

PROXY_CONFIG_DIR = "ns-metadata-proxy"
_HAPROXY_CONFIG_TEMPLATE = comm_meta.METADATA_HAPROXY_GLOBAL + """

listen listener
    bind %(host)s:%(port)s
    %(bind_v6_line)s
    server metadata %(unix_socket_path)s
    http-request del-header X-Neutron-%(res_type_del)s-ID
    http-request set-header X-Neutron-%(res_type)s-ID %(res_id)s
"""


class HaproxyConfigurator(object):
    def __init__(self, network_id, router_id, unix_socket_path, host, port,
                 user, group, state_path, pid_file, host_v6=None,
                 bind_interface=None):
        self.network_id = network_id
        self.router_id = router_id
        if network_id is None and router_id is None:
            raise exceptions.NetworkIdOrRouterIdRequiredError()

        self.host = host
        self.host_v6 = host_v6
        self.bind_interface = bind_interface
        self.port = port
        self.user = user
        self.group = group
        self.state_path = state_path
        self.unix_socket_path = unix_socket_path
        self.pidfile = pid_file
        self.log_level = (
            'debug' if logging.is_debug_enabled(cfg.CONF) else 'info')
        # log-tag will cause entries to have the string pre-pended, so use
        # the uuid haproxy will be started with.  Additionally, if it
        # starts with "haproxy" then things will get logged to
        # /var/log/haproxy.log on Debian distros, instead of to syslog.
        uuid = network_id or router_id
        self.log_tag = "haproxy-" + METADATA_SERVICE_NAME + "-" + uuid

    def create_config_file(self):
        """Create the config file for haproxy."""
        # Need to convert uid/gid into username/group
        try:
            username = pwd.getpwuid(int(self.user)).pw_name
        except (ValueError, KeyError):
            try:
                username = pwd.getpwnam(self.user).pw_name
            except KeyError:
                raise comm_meta.InvalidUserOrGroupException(
                    _("Invalid user/uid: '%s'") % self.user)

        try:
            groupname = grp.getgrgid(int(self.group)).gr_name
        except (ValueError, KeyError):
            try:
                groupname = grp.getgrnam(self.group).gr_name
            except KeyError:
                raise comm_meta.InvalidUserOrGroupException(
                    _("Invalid group/gid: '%s'") % self.group)

        cfg_info = {
            'host': self.host,
            'port': self.port,
            'unix_socket_path': self.unix_socket_path,
            'user': username,
            'group': groupname,
            'pidfile': self.pidfile,
            'log_level': self.log_level,
            'log_tag': self.log_tag,
            'bind_v6_line': '',
        }
        if self.host_v6 and self.bind_interface:
            cfg_info['bind_v6_line'] = (
                'bind %s:%s interface %s' % (
                    self.host_v6, self.port, self.bind_interface)
            )
        # If using the network ID, delete any spurious router ID that might
        # have been in the request, same for network ID when using router ID.
        if self.network_id:
            cfg_info['res_type'] = 'Network'
            cfg_info['res_id'] = self.network_id
            cfg_info['res_type_del'] = 'Router'
        else:
            cfg_info['res_type'] = 'Router'
            cfg_info['res_id'] = self.router_id
            cfg_info['res_type_del'] = 'Network'

        haproxy_cfg = _HAPROXY_CONFIG_TEMPLATE % cfg_info
        LOG.debug("haproxy_cfg = %s", haproxy_cfg)
        cfg_dir = self.get_config_path(self.state_path)
        # uuid has to be included somewhere in the command line so that it can
        # be tracked by process_monitor.
        self.cfg_path = os.path.join(cfg_dir, "%s.conf" % cfg_info['res_id'])
        if not os.path.exists(cfg_dir):
            os.makedirs(cfg_dir)
        with open(self.cfg_path, "w") as cfg_file:
            cfg_file.write(haproxy_cfg)

    @staticmethod
    def get_config_path(state_path):
        return os.path.join(state_path or cfg.CONF.state_path,
                            PROXY_CONFIG_DIR)

    @staticmethod
    def cleanup_config_file(uuid, state_path):
        """Delete config file created when metadata proxy was spawned."""
        # Delete config file if it exists
        cfg_path = os.path.join(
            HaproxyConfigurator.get_config_path(state_path),
            "%s.conf" % uuid)
        linux_utils.delete_if_exists(cfg_path, run_as_root=True)


class MetadataDriver(object):

    monitors = {}

    def __init__(self, l3_agent):
        self.metadata_port = l3_agent.conf.metadata_port
        self.metadata_access_mark = l3_agent.conf.metadata_access_mark
        registry.subscribe(
            after_router_added, resources.ROUTER, events.AFTER_CREATE)
        registry.subscribe(
            after_router_updated, resources.ROUTER, events.AFTER_UPDATE)
        registry.subscribe(
            before_router_removed, resources.ROUTER, events.BEFORE_DELETE)

    @classmethod
    def metadata_filter_rules(cls, port, mark):
        return [('INPUT', '-m mark --mark %s/%s -j ACCEPT' %
                 (mark, constants.ROUTER_MARK_MASK)),
                ('INPUT', '-p tcp -m tcp --dport %s '
                 '-j DROP' % port)]

    @classmethod
    def metadata_nat_rules(
            cls, port, metadata_address=constants.METADATA_V4_CIDR):
        return [('PREROUTING', '-d %(metadata_address)s '
                 '-i %(interface_name)s '
                 '-p tcp -m tcp --dport 80 -j REDIRECT '
                 '--to-ports %(port)s' %
                 {'metadata_address': metadata_address,
                  'interface_name': namespaces.INTERNAL_DEV_PREFIX + '+',
                  'port': port})]

    @classmethod
    def _get_metadata_proxy_user_group(cls, conf):
        user = conf.metadata_proxy_user or str(os.geteuid())
        group = conf.metadata_proxy_group or str(os.getegid())

        return user, group

    @classmethod
    def _get_metadata_proxy_callback(cls, bind_address, port, conf,
                                     network_id=None, router_id=None,
                                     bind_address_v6=None,
                                     bind_interface=None):
        def callback(pid_file):
            metadata_proxy_socket = conf.metadata_proxy_socket
            user, group = (
                cls._get_metadata_proxy_user_group(conf))
            haproxy = HaproxyConfigurator(network_id,
                                          router_id,
                                          metadata_proxy_socket,
                                          bind_address,
                                          port,
                                          user,
                                          group,
                                          conf.state_path,
                                          pid_file,
                                          bind_address_v6,
                                          bind_interface)
            haproxy.create_config_file()
            proxy_cmd = [HAPROXY_SERVICE,
                         '-f', haproxy.cfg_path]
            return proxy_cmd

        return callback

    @classmethod
    def spawn_monitored_metadata_proxy(cls, monitor, ns_name, port, conf,
                                       bind_address="0.0.0.0", network_id=None,
                                       router_id=None, bind_address_v6=None,
                                       bind_interface=None):
        if bind_interface is not None and bind_address_v6 is not None:
            # HAProxy cannot bind() until IPv6 Duplicate Address Detection
            # completes. We must wait until the address leaves its 'tentative'
            # state.
            try:
                ip_lib.IpAddrCommand(
                    parent=ip_lib.IPDevice(name=bind_interface,
                                           namespace=ns_name)
                ).wait_until_address_ready(address=bind_address_v6)
            except ip_lib.DADFailed as exc:
                # This failure means that another DHCP agent has already
                # configured this metadata address, so all requests will
                # be via that single agent.
                LOG.info('DAD failed for address %(address)s on interface '
                         '%(interface)s in namespace %(namespace)s on network '
                         '%(network)s, deleting it. Exception: %(exception)s',
                         {'address': bind_address_v6,
                          'interface': bind_interface,
                          'namespace': ns_name,
                          'network': network_id,
                          'exception': str(exc)})
                try:
                    ip_lib.delete_ip_address(bind_address_v6, bind_interface,
                                             namespace=ns_name)
                except Exception as exc:
                    # do not re-raise a delete failure, just log
                    LOG.info('Address deletion failure: %s', str(exc))

                # Do not use the address or interface when DAD fails
                bind_address_v6 = bind_interface = None

        uuid = network_id or router_id
        callback = cls._get_metadata_proxy_callback(
            bind_address, port, conf,
            network_id=network_id, router_id=router_id,
            bind_address_v6=bind_address_v6, bind_interface=bind_interface)
        pm = cls._get_metadata_proxy_process_manager(uuid, conf,
                                                     ns_name=ns_name,
                                                     callback=callback)
        pm.enable()
        monitor.register(uuid, METADATA_SERVICE_NAME, pm)
        cls.monitors[router_id] = pm

    @classmethod
    def destroy_monitored_metadata_proxy(cls, monitor, uuid, conf, ns_name):
        monitor.unregister(uuid, METADATA_SERVICE_NAME)
        pm = cls._get_metadata_proxy_process_manager(uuid, conf,
                                                     ns_name=ns_name)
        pm.disable(sig=str(int(signal.SIGTERM)))
        try:
            common_utils.wait_until_true(lambda: not pm.active,
                                         timeout=SIGTERM_TIMEOUT)
        except common_utils.WaitTimeout:
            LOG.warning('Metadata process %s did not finish after SIGTERM '
                        'signal in %s seconds, sending SIGKILL signal',
                        pm.pid, SIGTERM_TIMEOUT)
            pm.disable(sig=str(int(signal.SIGKILL)))

        # Delete metadata proxy config and PID files.
        HaproxyConfigurator.cleanup_config_file(uuid, cfg.CONF.state_path)
        linux_utils.delete_if_exists(pm.get_pid_file_name(), run_as_root=True)

        cls.monitors.pop(uuid, None)

    @classmethod
    def _get_metadata_proxy_process_manager(cls, router_id, conf, ns_name=None,
                                            callback=None):
        return external_process.ProcessManager(
            conf=conf,
            uuid=router_id,
            namespace=ns_name,
            service=HAPROXY_SERVICE,
            default_cmd_callback=callback)


def after_router_added(resource, event, l3_agent, payload):
    router = payload.latest_state
    proxy = l3_agent.metadata_driver
    apply_metadata_nat_rules(router, proxy)
    if not isinstance(router, ha_router.HaRouter):
        spawn_kwargs = {}
        if netutils.is_ipv6_enabled():
            spawn_kwargs['bind_address'] = '::'
        proxy.spawn_monitored_metadata_proxy(
            l3_agent.process_monitor,
            router.ns_name,
            proxy.metadata_port,
            l3_agent.conf,
            router_id=router.router_id,
            **spawn_kwargs)


def after_router_updated(resource, event, l3_agent, payload):
    router = payload.latest_state
    proxy = l3_agent.metadata_driver
    if (not proxy.monitors.get(router.router_id) and
            not isinstance(router, ha_router.HaRouter)):
        spawn_kwargs = {}
        if netutils.is_ipv6_enabled():
            spawn_kwargs['bind_address'] = '::'
        proxy.spawn_monitored_metadata_proxy(
            l3_agent.process_monitor,
            router.ns_name,
            proxy.metadata_port,
            l3_agent.conf,
            router_id=router.router_id,
            **spawn_kwargs)


def before_router_removed(resource, event, l3_agent, payload=None):
    router = payload.latest_state
    proxy = l3_agent.metadata_driver

    proxy.destroy_monitored_metadata_proxy(l3_agent.process_monitor,
                                           router.router['id'],
                                           l3_agent.conf,
                                           router.ns_name)


@coordination.synchronized('router-lock-ns-{router.ns_name}')
def apply_metadata_nat_rules(router, proxy):
    for c, r in proxy.metadata_filter_rules(proxy.metadata_port,
                                            proxy.metadata_access_mark):
        router.iptables_manager.ipv4['filter'].add_rule(c, r)
    if netutils.is_ipv6_enabled():
        for c, r in proxy.metadata_filter_rules(proxy.metadata_port,
                                                proxy.metadata_access_mark):
            router.iptables_manager.ipv6['filter'].add_rule(c, r)
    for c, r in proxy.metadata_nat_rules(proxy.metadata_port):
        router.iptables_manager.ipv4['nat'].add_rule(c, r)
    if netutils.is_ipv6_enabled():
        for c, r in proxy.metadata_nat_rules(
                proxy.metadata_port,
                metadata_address=(common_constants.METADATA_V6_CIDR)):
            router.iptables_manager.ipv6['nat'].add_rule(c, r)
    router.iptables_manager.apply()
