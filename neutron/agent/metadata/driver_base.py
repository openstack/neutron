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

import abc
import grp
import os
import pwd
import signal

from neutron_lib import exceptions
from oslo_config import cfg
from oslo_log import log as logging

from neutron._i18n import _
from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils as linux_utils
from neutron.common import metadata as comm_meta
from neutron.common import utils as common_utils


LOG = logging.getLogger(__name__)

SIGTERM_TIMEOUT = 5

METADATA_SERVICE_NAME = 'metadata-proxy'
HAPROXY_SERVICE = 'haproxy'

_UNLIMITED_CONFIG_TEMPLATE = """
listen listener
    bind %(host)s:%(port)s
    %(bind_v6_line)s
    server metadata %(unix_socket_path)s
"""


class HaproxyConfiguratorBase(metaclass=abc.ABCMeta):
    PROXY_CONFIG_DIR: str
    HEADER_CONFIG_TEMPLATE: str

    def __init__(self, network_id, router_id, unix_socket_path, host, port,
                 user, group, state_path, pid_file, rate_limiting_config,
                 host_v6=None, bind_interface=None):
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
        self.rate_limiting_config = rate_limiting_config
        self.log_level = (
            'debug' if logging.is_debug_enabled(cfg.CONF) else 'info')
        # log-tag will cause entries to have the string pre-pended, so use
        # the uuid haproxy will be started with.  Additionally, if it
        # starts with "haproxy" then things will get logged to
        # /var/log/haproxy.log on Debian distros, instead of to syslog.
        uuid = network_id or router_id
        self.log_tag = f"haproxy-{METADATA_SERVICE_NAME}-{uuid}"
        self._haproxy_cfg = ''
        self._resource_id = None
        self._create_config()

    @property
    def haproxy_cfg(self) -> str:
        return self._haproxy_cfg

    @property
    def resource_id(self) -> str:
        return self._resource_id

    def _create_config(self) -> None:
        """Create the configuration for haproxy, stored locally

        This method creates a string with the HAProxy configuration, stored in
        ``self._haproxy_cfg``. It also stores the resource ID (network, router)
        in ``self._resource_id``.

        This method must be called once in the init method.
        """
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
                'bind {}:{} interface {}'.format(
                    self.host_v6, self.port, self.bind_interface)
            )
        # If using the network ID, delete any spurious router ID that might
        # have been in the request, same for network ID when using router ID.
        # This is to prevent someone from spoofing a metadata request using
        # the proxy via an external network. See LP #1865036 for more info.
        # This only applies to the non-OVN driver.
        if self.network_id:
            cfg_info['res_type'] = 'Network'
            cfg_info['res_id'] = self.network_id
            cfg_info['res_type_del'] = 'Router'
        else:
            cfg_info['res_type'] = 'Router'
            cfg_info['res_id'] = self.router_id
            cfg_info['res_type_del'] = 'Network'
        self._resource_id = cfg_info['res_id']
        self._haproxy_cfg = comm_meta.get_haproxy_config(
            cfg_info, self.rate_limiting_config,
            self.HEADER_CONFIG_TEMPLATE, _UNLIMITED_CONFIG_TEMPLATE)

    def create_config_file(self):
        """Read the configuration stored and write the configuration file"""
        LOG.debug("haproxy_cfg = %s", self.haproxy_cfg)
        cfg_dir = self.get_config_path(self.state_path)
        # uuid has to be included somewhere in the command line so that it can
        # be tracked by process_monitor.
        self.cfg_path = os.path.join(cfg_dir, "%s.conf" % self.resource_id)
        if not os.path.exists(cfg_dir):
            os.makedirs(cfg_dir)
        with open(self.cfg_path, "w") as cfg_file:
            cfg_file.write(self.haproxy_cfg)

    @classmethod
    def get_config_path(cls, state_path):
        return os.path.join(state_path or cfg.CONF.state_path,
                            cls.PROXY_CONFIG_DIR)

    def read_config_file(self) -> str:
        """Return a string with the content of the configuration file"""
        cfg_path = os.path.join(self.get_config_path(self.state_path),
                                '%s.conf' % self.resource_id)
        return linux_utils.read_if_exists(str(cfg_path), run_as_root=True)

    def is_config_file_obsolete(self) -> bool:
        """Compare the instance config and the config file content

        Returns False if both configurations match. This check skips the
        "pidfile" line because that is provided just before the process is
        started.
        """
        def trim_config(haproxy_cfg: str) -> list[str]:
            return [line for line in haproxy_cfg.split('\n')
                    if not line.lstrip().startswith('pidfile')]

        file_config = trim_config(self.read_config_file())
        current_config = trim_config(self.haproxy_cfg)
        return file_config != current_config

    @classmethod
    def cleanup_config_file(cls, uuid, state_path):
        """Delete config file created when metadata proxy was spawned."""
        # Delete config file if it exists
        cfg_path = os.path.join(
            cls.get_config_path(state_path),
            "%s.conf" % uuid)
        linux_utils.delete_if_exists(cfg_path, run_as_root=True)


class MetadataDriverBase(metaclass=abc.ABCMeta):
    monitors = {}

    @staticmethod
    @abc.abstractmethod
    def haproxy_configurator():
        """Returns the HaproxyConfigurator for the class."""
        pass

    @classmethod
    def _get_metadata_proxy_user_group(cls, conf):
        user = conf.metadata_proxy_user or str(os.geteuid())
        group = conf.metadata_proxy_group or str(os.getegid())

        return user, group

    @classmethod
    def _get_haproxy_configurator(cls, bind_address, port, conf,
                                  network_id=None, router_id=None,
                                  bind_address_v6=None,
                                  bind_interface=None,
                                  pid_file=''):
        metadata_proxy_socket = conf.metadata_proxy_socket
        user, group = cls._get_metadata_proxy_user_group(conf)
        configurator = cls.haproxy_configurator()
        return configurator(network_id,
                            router_id,
                            metadata_proxy_socket,
                            bind_address,
                            port,
                            user,
                            group,
                            conf.state_path,
                            pid_file,
                            conf.metadata_rate_limiting,
                            bind_address_v6,
                            bind_interface)

    @classmethod
    def _get_metadata_proxy_callback(cls, bind_address, port, conf,
                                     network_id=None, router_id=None,
                                     bind_address_v6=None,
                                     bind_interface=None):
        def callback(pid_file):
            haproxy = cls._get_haproxy_configurator(
                bind_address, port, conf, network_id, router_id,
                bind_address_v6, bind_interface, pid_file)
            haproxy.create_config_file()
            return [HAPROXY_SERVICE, '-f', haproxy.cfg_path]

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

        # If the HAProxy running instance configuration is different from
        # the one passed in this call, the HAProxy is stopped. The new
        # configuration will be written to the disk and a new instance
        # started.
        haproxy_cfg = cls._get_haproxy_configurator(
            bind_address, port, conf, network_id=network_id,
            router_id=router_id, bind_address_v6=bind_address_v6,
            bind_interface=bind_interface)
        if haproxy_cfg.is_config_file_obsolete():
            cls.destroy_monitored_metadata_proxy(
                monitor, haproxy_cfg.resource_id, conf, ns_name)

        uuid = network_id or router_id
        callback = cls._get_metadata_proxy_callback(
            bind_address, port, conf,
            network_id=network_id, router_id=router_id,
            bind_address_v6=bind_address_v6, bind_interface=bind_interface)
        pm = cls._get_metadata_proxy_process_manager(uuid, conf,
                                                     ns_name=ns_name,
                                                     callback=callback)
        try:
            pm.enable(ensure_active=True)
        except exceptions.ProcessExecutionError as exec_err:
            LOG.error("Encountered process execution error %(err)s while "
                      "starting process in namespace %(ns)s",
                      {"err": exec_err, "ns": ns_name})
            return
        monitor.register(uuid, METADATA_SERVICE_NAME, pm)

        cls.monitors[uuid] = pm

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

        # Delete metadata proxy config.
        configurator = cls.haproxy_configurator()
        configurator.cleanup_config_file(uuid, cfg.CONF.state_path)

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
