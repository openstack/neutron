# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack Foundation
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
import collections
import os
import re
import shutil
import socket
import sys
import uuid

import netaddr
from oslo.config import cfg
import six

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import constants
from neutron.common import exceptions
from neutron.openstack.common import importutils
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('dhcp_confs',
               default='$state_path/dhcp',
               help=_('Location to store DHCP server config files')),
    cfg.StrOpt('dhcp_domain',
               default='openstacklocal',
               help=_('Domain to use for building the hostnames')),
    cfg.StrOpt('dnsmasq_config_file',
               default='',
               help=_('Override the default dnsmasq settings with this file')),
    cfg.ListOpt('dnsmasq_dns_servers',
                help=_('Comma-separated list of the DNS servers which will be '
                       'used as forwarders.'),
                deprecated_name='dnsmasq_dns_server'),
    cfg.BoolOpt('dhcp_delete_namespaces', default=False,
                help=_("Delete namespace after removing a dhcp server.")),
    cfg.IntOpt(
        'dnsmasq_lease_max',
        default=(2 ** 24),
        help=_('Limit number of leases to prevent a denial-of-service.')),
]

IPV4 = 4
IPV6 = 6
UDP = 'udp'
TCP = 'tcp'
DNS_PORT = 53
DHCPV4_PORT = 67
DHCPV6_PORT = 547
METADATA_DEFAULT_PREFIX = 16
METADATA_DEFAULT_IP = '169.254.169.254'
METADATA_DEFAULT_CIDR = '%s/%d' % (METADATA_DEFAULT_IP,
                                   METADATA_DEFAULT_PREFIX)
METADATA_PORT = 80
WIN2k3_STATIC_DNS = 249
NS_PREFIX = 'qdhcp-'


class DictModel(object):
    """Convert dict into an object that provides attribute access to values."""
    def __init__(self, d):
        for key, value in d.iteritems():
            if isinstance(value, list):
                value = [DictModel(item) if isinstance(item, dict) else item
                         for item in value]
            elif isinstance(value, dict):
                value = DictModel(value)

            setattr(self, key, value)


class NetModel(DictModel):

    def __init__(self, use_namespaces, d):
        super(NetModel, self).__init__(d)

        self._ns_name = (use_namespaces and
                         "%s%s" % (NS_PREFIX, self.id) or None)

    @property
    def namespace(self):
        return self._ns_name


@six.add_metaclass(abc.ABCMeta)
class DhcpBase(object):

    def __init__(self, conf, network, root_helper='sudo',
                 version=None, plugin=None):
        self.conf = conf
        self.network = network
        self.root_helper = root_helper
        self.device_manager = DeviceManager(self.conf,
                                            self.root_helper, plugin)
        self.version = version

    @abc.abstractmethod
    def enable(self):
        """Enables DHCP for this network."""

    @abc.abstractmethod
    def disable(self, retain_port=False):
        """Disable dhcp for this network."""

    def restart(self):
        """Restart the dhcp service for the network."""
        self.disable(retain_port=True)
        self.enable()

    @abc.abstractproperty
    def active(self):
        """Boolean representing the running state of the DHCP server."""

    @abc.abstractmethod
    def reload_allocations(self):
        """Force the DHCP server to reload the assignment database."""

    @classmethod
    def existing_dhcp_networks(cls, conf, root_helper):
        """Return a list of existing networks ids that we have configs for."""

        raise NotImplementedError

    @classmethod
    def check_version(cls):
        """Execute version checks on DHCP server."""

        raise NotImplementedError


class DhcpLocalProcess(DhcpBase):
    PORTS = []

    def _enable_dhcp(self):
        """check if there is a subnet within the network with dhcp enabled."""
        for subnet in self.network.subnets:
            if subnet.enable_dhcp:
                return True
        return False

    def enable(self):
        """Enables DHCP for this network by spawning a local process."""
        interface_name = self.device_manager.setup(self.network,
                                                   reuse_existing=True)
        if self.active:
            self.restart()
        elif self._enable_dhcp():
            self.interface_name = interface_name
            self.spawn_process()

    def disable(self, retain_port=False):
        """Disable DHCP for this network by killing the local process."""
        pid = self.pid

        if self.active:
            cmd = ['kill', '-9', pid]
            utils.execute(cmd, self.root_helper)
            if not retain_port:
                self.device_manager.destroy(self.network, self.interface_name)

        elif pid:
            LOG.debug(_('DHCP for %(net_id)s pid %(pid)d is stale, ignoring '
                        'command'), {'net_id': self.network.id, 'pid': pid})
        else:
            LOG.debug(_('No DHCP started for %s'), self.network.id)

        self._remove_config_files()

        if not retain_port:
            if self.conf.dhcp_delete_namespaces and self.network.namespace:
                ns_ip = ip_lib.IPWrapper(self.root_helper,
                                         self.network.namespace)
                try:
                    ns_ip.netns.delete(self.network.namespace)
                except RuntimeError:
                    msg = _('Failed trying to delete namespace: %s')
                    LOG.exception(msg, self.network.namespace)

    def _remove_config_files(self):
        confs_dir = os.path.abspath(os.path.normpath(self.conf.dhcp_confs))
        conf_dir = os.path.join(confs_dir, self.network.id)
        shutil.rmtree(conf_dir, ignore_errors=True)

    def get_conf_file_name(self, kind, ensure_conf_dir=False):
        """Returns the file name for a given kind of config file."""
        confs_dir = os.path.abspath(os.path.normpath(self.conf.dhcp_confs))
        conf_dir = os.path.join(confs_dir, self.network.id)
        if ensure_conf_dir:
            if not os.path.isdir(conf_dir):
                os.makedirs(conf_dir, 0o755)

        return os.path.join(conf_dir, kind)

    def _get_value_from_conf_file(self, kind, converter=None):
        """A helper function to read a value from one of the state files."""
        file_name = self.get_conf_file_name(kind)
        msg = _('Error while reading %s')

        try:
            with open(file_name, 'r') as f:
                try:
                    return converter and converter(f.read()) or f.read()
                except ValueError:
                    msg = _('Unable to convert value in %s')
        except IOError:
            msg = _('Unable to access %s')

        LOG.debug(msg % file_name)
        return None

    @property
    def pid(self):
        """Last known pid for the DHCP process spawned for this network."""
        return self._get_value_from_conf_file('pid', int)

    @property
    def active(self):
        pid = self.pid
        if pid is None:
            return False

        cmdline = '/proc/%s/cmdline' % pid
        try:
            with open(cmdline, "r") as f:
                return self.network.id in f.readline()
        except IOError:
            return False

    @property
    def interface_name(self):
        return self._get_value_from_conf_file('interface')

    @interface_name.setter
    def interface_name(self, value):
        interface_file_path = self.get_conf_file_name('interface',
                                                      ensure_conf_dir=True)
        utils.replace_file(interface_file_path, value)

    @abc.abstractmethod
    def spawn_process(self):
        pass


class Dnsmasq(DhcpLocalProcess):
    # The ports that need to be opened when security policies are active
    # on the Neutron port used for DHCP.  These are provided as a convenience
    # for users of this class.
    PORTS = {IPV4: [(UDP, DNS_PORT), (TCP, DNS_PORT), (UDP, DHCPV4_PORT)],
             IPV6: [(UDP, DNS_PORT), (TCP, DNS_PORT), (UDP, DHCPV6_PORT)],
             }

    _TAG_PREFIX = 'tag%d'

    NEUTRON_NETWORK_ID_KEY = 'NEUTRON_NETWORK_ID'
    NEUTRON_RELAY_SOCKET_PATH_KEY = 'NEUTRON_RELAY_SOCKET_PATH'
    MINIMUM_VERSION = 2.59

    @classmethod
    def check_version(cls):
        ver = 0
        try:
            cmd = ['dnsmasq', '--version']
            out = utils.execute(cmd)
            ver = re.findall("\d+.\d+", out)[0]
            is_valid_version = float(ver) >= cls.MINIMUM_VERSION
            if not is_valid_version:
                LOG.warning(_('FAILED VERSION REQUIREMENT FOR DNSMASQ. '
                              'DHCP AGENT MAY NOT RUN CORRECTLY! '
                              'Please ensure that its version is %s '
                              'or above!'), cls.MINIMUM_VERSION)
        except (OSError, RuntimeError, IndexError, ValueError):
            LOG.warning(_('Unable to determine dnsmasq version. '
                          'Please ensure that its version is %s '
                          'or above!'), cls.MINIMUM_VERSION)
        return float(ver)

    @classmethod
    def existing_dhcp_networks(cls, conf, root_helper):
        """Return a list of existing networks ids that we have configs for."""

        confs_dir = os.path.abspath(os.path.normpath(conf.dhcp_confs))

        return [
            c for c in os.listdir(confs_dir)
            if uuidutils.is_uuid_like(c)
        ]

    def spawn_process(self):
        """Spawns a Dnsmasq process for the network."""
        env = {
            self.NEUTRON_NETWORK_ID_KEY: self.network.id,
        }

        cmd = [
            'dnsmasq',
            '--no-hosts',
            '--no-resolv',
            '--strict-order',
            '--bind-interfaces',
            '--interface=%s' % self.interface_name,
            '--except-interface=lo',
            '--pid-file=%s' % self.get_conf_file_name(
                'pid', ensure_conf_dir=True),
            '--dhcp-hostsfile=%s' % self._output_hosts_file(),
            '--addn-hosts=%s' % self._output_addn_hosts_file(),
            '--dhcp-optsfile=%s' % self._output_opts_file(),
            '--leasefile-ro',
        ]

        possible_leases = 0
        for i, subnet in enumerate(self.network.subnets):
            # if a subnet is specified to have dhcp disabled
            if not subnet.enable_dhcp:
                continue
            if subnet.ip_version == 4:
                mode = 'static'
            else:
                # TODO(mark): how do we indicate other options
                # ra-only, slaac, ra-nameservers, and ra-stateless.
                mode = 'static'
            if self.version >= self.MINIMUM_VERSION:
                set_tag = 'set:'
            else:
                set_tag = ''

            cidr = netaddr.IPNetwork(subnet.cidr)

            cmd.append('--dhcp-range=%s%s,%s,%s,%ss' %
                       (set_tag, self._TAG_PREFIX % i,
                        cidr.network,
                        mode,
                        self.conf.dhcp_lease_duration))
            possible_leases += cidr.size

        # Cap the limit because creating lots of subnets can inflate
        # this possible lease cap.
        cmd.append('--dhcp-lease-max=%d' %
                   min(possible_leases, self.conf.dnsmasq_lease_max))

        cmd.append('--conf-file=%s' % self.conf.dnsmasq_config_file)
        if self.conf.dnsmasq_dns_servers:
            cmd.extend(
                '--server=%s' % server
                for server in self.conf.dnsmasq_dns_servers)

        if self.conf.dhcp_domain:
            cmd.append('--domain=%s' % self.conf.dhcp_domain)

        ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                      self.network.namespace)
        ip_wrapper.netns.execute(cmd, addl_env=env)

    def _release_lease(self, mac_address, ip):
        """Release a DHCP lease."""
        cmd = ['dhcp_release', self.interface_name, ip, mac_address]
        ip_wrapper = ip_lib.IPWrapper(self.root_helper,
                                      self.network.namespace)
        ip_wrapper.netns.execute(cmd)

    def reload_allocations(self):
        """Rebuild the dnsmasq config and signal the dnsmasq to reload."""

        # If all subnets turn off dhcp, kill the process.
        if not self._enable_dhcp():
            self.disable()
            LOG.debug(_('Killing dhcpmasq for network since all subnets have '
                        'turned off DHCP: %s'), self.network.id)
            return

        self._release_unused_leases()
        self._output_hosts_file()
        self._output_addn_hosts_file()
        self._output_opts_file()
        if self.active:
            cmd = ['kill', '-HUP', self.pid]
            utils.execute(cmd, self.root_helper)
        else:
            LOG.debug(_('Pid %d is stale, relaunching dnsmasq'), self.pid)
        LOG.debug(_('Reloading allocations for network: %s'), self.network.id)
        self.device_manager.update(self.network, self.interface_name)

    def _iter_hosts(self):
        """Iterate over hosts.

        For each host on the network we yield a tuple containing:
        (
            port,  # a DictModel instance representing the port.
            alloc,  # a DictModel instance of the allocated ip and subnet.
            host_name,  # Host name.
            name,  # Host name and domain name in the format 'hostname.domain'.
        )
        """
        for port in self.network.ports:
            for alloc in port.fixed_ips:
                hostname = 'host-%s' % alloc.ip_address.replace(
                    '.', '-').replace(':', '-')
                fqdn = '%s.%s' % (hostname, self.conf.dhcp_domain)
                yield (port, alloc, hostname, fqdn)

    def _output_hosts_file(self):
        """Writes a dnsmasq compatible dhcp hosts file.

        The generated file is sent to the --dhcp-hostsfile option of dnsmasq,
        and lists the hosts on the network which should receive a dhcp lease.
        Each line in this file is in the form::

            'mac_address,FQDN,ip_address'

        IMPORTANT NOTE: a dnsmasq instance does not resolve hosts defined in
        this file if it did not give a lease to a host listed in it (e.g.:
        multiple dnsmasq instances on the same network if this network is on
        multiple network nodes). This file is only defining hosts which
        should receive a dhcp lease, the hosts resolution in itself is
        defined by the `_output_addn_hosts_file` method.
        """
        buf = six.StringIO()
        filename = self.get_conf_file_name('host')

        LOG.debug(_('Building host file: %s'), filename)
        for (port, alloc, hostname, name) in self._iter_hosts():
            set_tag = ''
            # (dzyu) Check if it is legal ipv6 address, if so, need wrap
            # it with '[]' to let dnsmasq to distinguish MAC address from
            # IPv6 address.
            ip_address = alloc.ip_address
            if netaddr.valid_ipv6(ip_address):
                ip_address = '[%s]' % ip_address

            LOG.debug(_('Adding %(mac)s : %(name)s : %(ip)s'),
                      {"mac": port.mac_address, "name": name,
                       "ip": ip_address})

            if getattr(port, 'extra_dhcp_opts', False):
                if self.version >= self.MINIMUM_VERSION:
                    set_tag = 'set:'

                buf.write('%s,%s,%s,%s%s\n' %
                          (port.mac_address, name, ip_address,
                           set_tag, port.id))
            else:
                buf.write('%s,%s,%s\n' %
                          (port.mac_address, name, ip_address))

        utils.replace_file(filename, buf.getvalue())
        LOG.debug(_('Done building host file %s'), filename)
        return filename

    def _read_hosts_file_leases(self, filename):
        leases = set()
        if os.path.exists(filename):
            with open(filename) as f:
                for l in f.readlines():
                    host = l.strip().split(',')
                    leases.add((host[2], host[0]))
        return leases

    def _release_unused_leases(self):
        filename = self.get_conf_file_name('host')
        old_leases = self._read_hosts_file_leases(filename)

        new_leases = set()
        for port in self.network.ports:
            for alloc in port.fixed_ips:
                new_leases.add((alloc.ip_address, port.mac_address))

        for ip, mac in old_leases - new_leases:
            self._release_lease(mac, ip)

    def _output_addn_hosts_file(self):
        """Writes a dnsmasq compatible additional hosts file.

        The generated file is sent to the --addn-hosts option of dnsmasq,
        and lists the hosts on the network which should be resolved even if
        the dnsmaq instance did not give a lease to the host (see the
        `_output_hosts_file` method).
        Each line in this file is in the same form as a standard /etc/hosts
        file.
        """
        buf = six.StringIO()
        for (port, alloc, hostname, fqdn) in self._iter_hosts():
            # It is compulsory to write the `fqdn` before the `hostname` in
            # order to obtain it in PTR responses.
            buf.write('%s\t%s %s\n' % (alloc.ip_address, fqdn, hostname))
        addn_hosts = self.get_conf_file_name('addn_hosts')
        utils.replace_file(addn_hosts, buf.getvalue())
        return addn_hosts

    def _output_opts_file(self):
        """Write a dnsmasq compatible options file."""

        if self.conf.enable_isolated_metadata:
            subnet_to_interface_ip = self._make_subnet_interface_ip_map()

        options = []

        dhcp_ips = collections.defaultdict(list)
        subnet_idx_map = {}
        for i, subnet in enumerate(self.network.subnets):
            if not subnet.enable_dhcp:
                continue
            if subnet.dns_nameservers:
                options.append(
                    self._format_option(i, 'dns-server',
                                        ','.join(subnet.dns_nameservers)))
            else:
                # use the dnsmasq ip as nameservers only if there is no
                # dns-server submitted by the server
                subnet_idx_map[subnet.id] = i

            gateway = subnet.gateway_ip
            host_routes = []
            for hr in subnet.host_routes:
                if hr.destination == "0.0.0.0/0":
                    gateway = hr.nexthop
                else:
                    host_routes.append("%s,%s" % (hr.destination, hr.nexthop))

            # Add host routes for isolated network segments

            if self._enable_metadata(subnet):
                subnet_dhcp_ip = subnet_to_interface_ip[subnet.id]
                host_routes.append(
                    '%s/32,%s' % (METADATA_DEFAULT_IP, subnet_dhcp_ip)
                )

            if host_routes:
                options.append(
                    self._format_option(i, 'classless-static-route',
                                        ','.join(host_routes)))
                options.append(
                    self._format_option(i, WIN2k3_STATIC_DNS,
                                        ','.join(host_routes)))

            if subnet.ip_version == 4:
                if gateway:
                    options.append(self._format_option(i, 'router', gateway))
                else:
                    options.append(self._format_option(i, 'router'))

        for port in self.network.ports:
            if getattr(port, 'extra_dhcp_opts', False):
                options.extend(
                    self._format_option(port.id, opt.opt_name, opt.opt_value)
                    for opt in port.extra_dhcp_opts)

            # provides all dnsmasq ip as dns-server if there is more than
            # one dnsmasq for a subnet and there is no dns-server submitted
            # by the server
            if port.device_owner == constants.DEVICE_OWNER_DHCP:
                for ip in port.fixed_ips:
                    i = subnet_idx_map.get(ip.subnet_id)
                    if i is None:
                        continue
                    dhcp_ips[i].append(ip.ip_address)

        for i, ips in dhcp_ips.items():
            if len(ips) > 1:
                options.append(self._format_option(i,
                                                   'dns-server',
                                                   ','.join(ips)))

        name = self.get_conf_file_name('opts')
        utils.replace_file(name, '\n'.join(options))
        return name

    def _make_subnet_interface_ip_map(self):
        ip_dev = ip_lib.IPDevice(
            self.interface_name,
            self.root_helper,
            self.network.namespace
        )

        subnet_lookup = dict(
            (netaddr.IPNetwork(subnet.cidr), subnet.id)
            for subnet in self.network.subnets
        )

        retval = {}

        for addr in ip_dev.addr.list():
            ip_net = netaddr.IPNetwork(addr['cidr'])

            if ip_net in subnet_lookup:
                retval[subnet_lookup[ip_net]] = addr['cidr'].split('/')[0]

        return retval

    def _format_option(self, tag, option, *args):
        """Format DHCP option by option name or code."""
        if self.version >= self.MINIMUM_VERSION:
            set_tag = 'tag:'
        else:
            set_tag = ''

        option = str(option)

        if isinstance(tag, int):
            tag = self._TAG_PREFIX % tag

        if not option.isdigit():
            option = 'option:%s' % option

        return ','.join((set_tag + tag, '%s' % option) + args)

    def _enable_metadata(self, subnet):
        '''Determine if the metadata route will be pushed to hosts on subnet.

        If subnet has a Neutron router attached, we want the hosts to get
        metadata from the router's proxy via their default route instead.
        '''
        if self.conf.enable_isolated_metadata and subnet.ip_version == 4:
            if subnet.gateway_ip is None:
                return True
            else:
                for port in self.network.ports:
                    if port.device_owner == constants.DEVICE_OWNER_ROUTER_INTF:
                        for alloc in port.fixed_ips:
                            if alloc.subnet_id == subnet.id:
                                return False
                return True
        else:
            return False

    @classmethod
    def lease_update(cls):
        network_id = os.environ.get(cls.NEUTRON_NETWORK_ID_KEY)
        dhcp_relay_socket = os.environ.get(cls.NEUTRON_RELAY_SOCKET_PATH_KEY)

        action = sys.argv[1]
        if action not in ('add', 'del', 'old'):
            sys.exit()

        mac_address = sys.argv[2]
        ip_address = sys.argv[3]

        if action == 'del':
            lease_remaining = 0
        else:
            lease_remaining = int(os.environ.get('DNSMASQ_TIME_REMAINING', 0))

        data = dict(network_id=network_id, mac_address=mac_address,
                    ip_address=ip_address, lease_remaining=lease_remaining)

        if os.path.exists(dhcp_relay_socket):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(dhcp_relay_socket)
            sock.send(jsonutils.dumps(data))
            sock.close()


class DeviceManager(object):

    def __init__(self, conf, root_helper, plugin):
        self.conf = conf
        self.root_helper = root_helper
        self.plugin = plugin
        if not conf.interface_driver:
            msg = _('An interface driver must be specified')
            LOG.error(msg)
            raise SystemExit(msg)
        try:
            self.driver = importutils.import_object(
                conf.interface_driver, conf)
        except Exception as e:
            msg = (_("Error importing interface driver '%(driver)s': "
                   "%(inner)s") % {'driver': conf.interface_driver,
                                   'inner': e})
            LOG.error(msg)
            raise SystemExit(msg)

    def get_interface_name(self, network, port):
        """Return interface(device) name for use by the DHCP process."""
        return self.driver.get_device_name(port)

    def get_device_id(self, network):
        """Return a unique DHCP device ID for this host on the network."""
        # There could be more than one dhcp server per network, so create
        # a device id that combines host and network ids

        host_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname())
        return 'dhcp%s-%s' % (host_uuid, network.id)

    def _set_default_route(self, network, device_name):
        """Sets the default gateway for this dhcp namespace.

        This method is idempotent and will only adjust the route if adjusting
        it would change it from what it already is.  This makes it safe to call
        and avoids unnecessary perturbation of the system.
        """
        device = ip_lib.IPDevice(device_name,
                                 self.root_helper,
                                 network.namespace)
        gateway = device.route.get_gateway()
        if gateway:
            gateway = gateway['gateway']

        for subnet in network.subnets:
            skip_subnet = (
                subnet.ip_version != 4
                or not subnet.enable_dhcp
                or subnet.gateway_ip is None)

            if skip_subnet:
                continue

            if gateway != subnet.gateway_ip:
                m = _('Setting gateway for dhcp netns on net %(n)s to %(ip)s')
                LOG.debug(m, {'n': network.id, 'ip': subnet.gateway_ip})

                device.route.add_gateway(subnet.gateway_ip)

            return

        # No subnets on the network have a valid gateway.  Clean it up to avoid
        # confusion from seeing an invalid gateway here.
        if gateway is not None:
            msg = _('Removing gateway for dhcp netns on net %s')
            LOG.debug(msg, network.id)

            device.route.delete_gateway(gateway)

    def setup_dhcp_port(self, network):
        """Create/update DHCP port for the host if needed and return port."""

        device_id = self.get_device_id(network)
        subnets = {}
        dhcp_enabled_subnet_ids = []
        for subnet in network.subnets:
            if subnet.enable_dhcp:
                dhcp_enabled_subnet_ids.append(subnet.id)
                subnets[subnet.id] = subnet

        dhcp_port = None
        for port in network.ports:
            port_device_id = getattr(port, 'device_id', None)
            if port_device_id == device_id:
                port_fixed_ips = []
                for fixed_ip in port.fixed_ips:
                    port_fixed_ips.append({'subnet_id': fixed_ip.subnet_id,
                                           'ip_address': fixed_ip.ip_address})
                    if fixed_ip.subnet_id in dhcp_enabled_subnet_ids:
                        dhcp_enabled_subnet_ids.remove(fixed_ip.subnet_id)

                # If there are dhcp_enabled_subnet_ids here that means that
                # we need to add those to the port and call update.
                if dhcp_enabled_subnet_ids:
                    port_fixed_ips.extend(
                        [dict(subnet_id=s) for s in dhcp_enabled_subnet_ids])
                    dhcp_port = self.plugin.update_dhcp_port(
                        port.id, {'port': {'fixed_ips': port_fixed_ips}})
                    if not dhcp_port:
                        raise exceptions.Conflict()
                else:
                    dhcp_port = port
                # break since we found port that matches device_id
                break

        # DHCP port has not yet been created.
        if dhcp_port is None:
            LOG.debug(_('DHCP port %(device_id)s on network %(network_id)s'
                        ' does not yet exist.'), {'device_id': device_id,
                                                  'network_id': network.id})
            port_dict = dict(
                name='',
                admin_state_up=True,
                device_id=device_id,
                network_id=network.id,
                tenant_id=network.tenant_id,
                fixed_ips=[dict(subnet_id=s) for s in dhcp_enabled_subnet_ids])
            dhcp_port = self.plugin.create_dhcp_port({'port': port_dict})

        if not dhcp_port:
            raise exceptions.Conflict()

        # Convert subnet_id to subnet dict
        fixed_ips = [dict(subnet_id=fixed_ip.subnet_id,
                          ip_address=fixed_ip.ip_address,
                          subnet=subnets[fixed_ip.subnet_id])
                     for fixed_ip in dhcp_port.fixed_ips]

        ips = [DictModel(item) if isinstance(item, dict) else item
               for item in fixed_ips]
        dhcp_port.fixed_ips = ips

        return dhcp_port

    def setup(self, network, reuse_existing=False):
        """Create and initialize a device for network's DHCP on this host."""
        port = self.setup_dhcp_port(network)
        interface_name = self.get_interface_name(network, port)

        if ip_lib.device_exists(interface_name,
                                self.root_helper,
                                network.namespace):
            if not reuse_existing:
                raise exceptions.PreexistingDeviceFailure(
                    dev_name=interface_name)

            LOG.debug(_('Reusing existing device: %s.'), interface_name)
        else:
            self.driver.plug(network.id,
                             port.id,
                             interface_name,
                             port.mac_address,
                             namespace=network.namespace)
        ip_cidrs = []
        for fixed_ip in port.fixed_ips:
            subnet = fixed_ip.subnet
            net = netaddr.IPNetwork(subnet.cidr)
            ip_cidr = '%s/%s' % (fixed_ip.ip_address, net.prefixlen)
            ip_cidrs.append(ip_cidr)

        if (self.conf.enable_isolated_metadata and
            self.conf.use_namespaces):
            ip_cidrs.append(METADATA_DEFAULT_CIDR)

        self.driver.init_l3(interface_name, ip_cidrs,
                            namespace=network.namespace)

        # ensure that the dhcp interface is first in the list
        if network.namespace is None:
            device = ip_lib.IPDevice(interface_name,
                                     self.root_helper)
            device.route.pullup_route(interface_name)

        if self.conf.use_namespaces:
            self._set_default_route(network, interface_name)

        return interface_name

    def update(self, network, device_name):
        """Update device settings for the network's DHCP on this host."""
        if self.conf.use_namespaces:
            self._set_default_route(network, device_name)

    def destroy(self, network, device_name):
        """Destroy the device used for the network's DHCP on this host."""
        self.driver.unplug(device_name, namespace=network.namespace)

        self.plugin.release_dhcp_port(network.id,
                                      self.get_device_id(network))
