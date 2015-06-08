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
import time

import netaddr
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils
import six

from neutron.agent.linux import external_process
from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_manager
from neutron.agent.linux import utils
from neutron.common import constants
from neutron.common import exceptions
from neutron.common import ipv6_utils
from neutron.common import utils as commonutils
from neutron.extensions import extra_dhcp_opt as edo_ext
from neutron.i18n import _LE, _LI, _LW
from neutron.openstack.common import uuidutils

LOG = logging.getLogger(__name__)

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
DNSMASQ_SERVICE_NAME = 'dnsmasq'


class DictModel(dict):
    """Convert dict into an object that provides attribute access to values."""

    def __init__(self, *args, **kwargs):
        """Convert dict values to DictModel values."""
        super(DictModel, self).__init__(*args, **kwargs)

        def needs_upgrade(item):
            """Check if `item` is a dict and needs to be changed to DictModel.
            """
            return isinstance(item, dict) and not isinstance(item, DictModel)

        def upgrade(item):
            """Upgrade item if it needs to be upgraded."""
            if needs_upgrade(item):
                return DictModel(item)
            else:
                return item

        for key, value in six.iteritems(self):
            if isinstance(value, (list, tuple)):
                # Keep the same type but convert dicts to DictModels
                self[key] = type(value)(
                    (upgrade(item) for item in value)
                )
            elif needs_upgrade(value):
                # Change dict instance values to DictModel instance values
                self[key] = DictModel(value)

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as e:
            raise AttributeError(e)

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        del self[name]


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

    def __init__(self, conf, network, process_monitor,
                 version=None, plugin=None):
        self.conf = conf
        self.network = network
        self.process_monitor = process_monitor
        self.device_manager = DeviceManager(self.conf, plugin)
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
    def existing_dhcp_networks(cls, conf):
        """Return a list of existing networks ids that we have configs for."""

        raise NotImplementedError()

    @classmethod
    def check_version(cls):
        """Execute version checks on DHCP server."""

        raise NotImplementedError()

    @classmethod
    def get_isolated_subnets(cls, network):
        """Returns a dict indicating whether or not a subnet is isolated"""
        raise NotImplementedError()

    @classmethod
    def should_enable_metadata(cls, conf, network):
        """True if the metadata-proxy should be enabled for the network."""
        raise NotImplementedError()


class DhcpLocalProcess(DhcpBase):
    PORTS = []

    def __init__(self, conf, network, process_monitor, version=None,
                 plugin=None):
        super(DhcpLocalProcess, self).__init__(conf, network, process_monitor,
                                               version, plugin)
        self.confs_dir = self.get_confs_dir(conf)
        self.network_conf_dir = os.path.join(self.confs_dir, network.id)
        utils.ensure_dir(self.network_conf_dir)

    @staticmethod
    def get_confs_dir(conf):
        return os.path.abspath(os.path.normpath(conf.dhcp_confs))

    def get_conf_file_name(self, kind):
        """Returns the file name for a given kind of config file."""
        return os.path.join(self.network_conf_dir, kind)

    def _remove_config_files(self):
        shutil.rmtree(self.network_conf_dir, ignore_errors=True)

    def _enable_dhcp(self):
        """check if there is a subnet within the network with dhcp enabled."""
        for subnet in self.network.subnets:
            if subnet.enable_dhcp:
                return True
        return False

    def enable(self):
        """Enables DHCP for this network by spawning a local process."""
        if self.active:
            self.restart()
        elif self._enable_dhcp():
            utils.ensure_dir(self.network_conf_dir)
            interface_name = self.device_manager.setup(self.network)
            self.interface_name = interface_name
            self.spawn_process()

    def _get_process_manager(self, cmd_callback=None):
        return external_process.ProcessManager(
            conf=self.conf,
            uuid=self.network.id,
            namespace=self.network.namespace,
            default_cmd_callback=cmd_callback,
            pid_file=self.get_conf_file_name('pid'),
            run_as_root=True)

    def disable(self, retain_port=False):
        """Disable DHCP for this network by killing the local process."""
        self.process_monitor.unregister(self.network.id, DNSMASQ_SERVICE_NAME)
        self._get_process_manager().disable()
        if not retain_port:
            self._destroy_namespace_and_port()
        self._remove_config_files()

    def _destroy_namespace_and_port(self):
        try:
            self.device_manager.destroy(self.network, self.interface_name)
        except RuntimeError:
            LOG.warning(_LW('Failed trying to delete interface: %s'),
                        self.interface_name)

        if self.conf.dhcp_delete_namespaces and self.network.namespace:
            ns_ip = ip_lib.IPWrapper(namespace=self.network.namespace)
            try:
                ns_ip.netns.delete(self.network.namespace)
            except RuntimeError:
                LOG.warning(_LW('Failed trying to delete namespace: %s'),
                            self.network.namespace)

    def _get_value_from_conf_file(self, kind, converter=None):
        """A helper function to read a value from one of the state files."""
        file_name = self.get_conf_file_name(kind)
        msg = _('Error while reading %s')

        try:
            with open(file_name, 'r') as f:
                try:
                    return converter(f.read()) if converter else f.read()
                except ValueError:
                    msg = _('Unable to convert value in %s')
        except IOError:
            msg = _('Unable to access %s')

        LOG.debug(msg, file_name)
        return None

    @property
    def interface_name(self):
        return self._get_value_from_conf_file('interface')

    @interface_name.setter
    def interface_name(self, value):
        interface_file_path = self.get_conf_file_name('interface')
        utils.replace_file(interface_file_path, value)

    @property
    def active(self):
        return self._get_process_manager().active

    @abc.abstractmethod
    def spawn_process(self):
        pass


class Dnsmasq(DhcpLocalProcess):
    # The ports that need to be opened when security policies are active
    # on the Neutron port used for DHCP.  These are provided as a convenience
    # for users of this class.
    PORTS = {constants.IP_VERSION_4:
             [(UDP, DNS_PORT), (TCP, DNS_PORT), (UDP, DHCPV4_PORT)],
             constants.IP_VERSION_6:
             [(UDP, DNS_PORT), (TCP, DNS_PORT), (UDP, DHCPV6_PORT)],
             }

    _TAG_PREFIX = 'tag%d'

    _ID = 'id:'

    @classmethod
    def check_version(cls):
        pass

    @classmethod
    def existing_dhcp_networks(cls, conf):
        """Return a list of existing networks ids that we have configs for."""
        confs_dir = cls.get_confs_dir(conf)
        try:
            return [
                c for c in os.listdir(confs_dir)
                if uuidutils.is_uuid_like(c)
            ]
        except OSError:
            return []

    def _build_cmdline_callback(self, pid_file):
        cmd = [
            'dnsmasq',
            '--no-hosts',
            '--no-resolv',
            '--strict-order',
            '--bind-interfaces',
            '--interface=%s' % self.interface_name,
            '--except-interface=lo',
            '--pid-file=%s' % pid_file,
            '--dhcp-hostsfile=%s' % self.get_conf_file_name('host'),
            '--addn-hosts=%s' % self.get_conf_file_name('addn_hosts'),
            '--dhcp-optsfile=%s' % self.get_conf_file_name('opts'),
            '--dhcp-leasefile=%s' % self.get_conf_file_name('leases'),
        ]

        possible_leases = 0
        for i, subnet in enumerate(self.network.subnets):
            mode = None
            # if a subnet is specified to have dhcp disabled
            if not subnet.enable_dhcp:
                continue
            if subnet.ip_version == 4:
                mode = 'static'
            else:
                # Note(scollins) If the IPv6 attributes are not set, set it as
                # static to preserve previous behavior
                addr_mode = getattr(subnet, 'ipv6_address_mode', None)
                ra_mode = getattr(subnet, 'ipv6_ra_mode', None)
                if (addr_mode in [constants.DHCPV6_STATEFUL,
                                  constants.DHCPV6_STATELESS] or
                        not addr_mode and not ra_mode):
                    mode = 'static'

            cidr = netaddr.IPNetwork(subnet.cidr)

            if self.conf.dhcp_lease_duration == -1:
                lease = 'infinite'
            else:
                lease = '%ss' % self.conf.dhcp_lease_duration

            # mode is optional and is not set - skip it
            if mode:
                if subnet.ip_version == 4:
                    cmd.append('--dhcp-range=%s%s,%s,%s,%s' %
                               ('set:', self._TAG_PREFIX % i,
                                cidr.network, mode, lease))
                else:
                    cmd.append('--dhcp-range=%s%s,%s,%s,%d,%s' %
                               ('set:', self._TAG_PREFIX % i,
                                cidr.network, mode,
                                cidr.prefixlen, lease))
                possible_leases += cidr.size

        if cfg.CONF.advertise_mtu:
            mtu = self.network.mtu
            # Do not advertise unknown mtu
            if mtu > 0:
                cmd.append('--dhcp-option-force=option:mtu,%d' % mtu)

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

        if self.conf.dhcp_broadcast_reply:
            cmd.append('--dhcp-broadcast')

        return cmd

    def spawn_process(self):
        """Spawn the process, if it's not spawned already."""
        # we only need to generate the lease file the first time dnsmasq starts
        # rather than on every reload since dnsmasq will keep the file current
        self._output_init_lease_file()
        self._spawn_or_reload_process(reload_with_HUP=False)

    def _spawn_or_reload_process(self, reload_with_HUP):
        """Spawns or reloads a Dnsmasq process for the network.

        When reload_with_HUP is True, dnsmasq receives a HUP signal,
        or it's reloaded if the process is not running.
        """

        self._output_config_files()

        pm = self._get_process_manager(
            cmd_callback=self._build_cmdline_callback)

        pm.enable(reload_cfg=reload_with_HUP)

        self.process_monitor.register(uuid=self.network.id,
                                      service_name=DNSMASQ_SERVICE_NAME,
                                      monitored_process=pm)

    def _release_lease(self, mac_address, ip, client_id):
        """Release a DHCP lease."""
        cmd = ['dhcp_release', self.interface_name, ip, mac_address]
        if client_id:
            cmd.append(client_id)
        ip_wrapper = ip_lib.IPWrapper(namespace=self.network.namespace)
        ip_wrapper.netns.execute(cmd, run_as_root=True)

    def _output_config_files(self):
        self._output_hosts_file()
        self._output_addn_hosts_file()
        self._output_opts_file()

    def reload_allocations(self):
        """Rebuild the dnsmasq config and signal the dnsmasq to reload."""

        # If all subnets turn off dhcp, kill the process.
        if not self._enable_dhcp():
            self.disable()
            LOG.debug('Killing dnsmasq for network since all subnets have '
                      'turned off DHCP: %s', self.network.id)
            return

        self._release_unused_leases()
        self._spawn_or_reload_process(reload_with_HUP=True)
        LOG.debug('Reloading allocations for network: %s', self.network.id)
        self.device_manager.update(self.network, self.interface_name)

    def _iter_hosts(self):
        """Iterate over hosts.

        For each host on the network we yield a tuple containing:
        (
            port,  # a DictModel instance representing the port.
            alloc,  # a DictModel instance of the allocated ip and subnet.
                    # if alloc is None, it means there is no need to allocate
                    # an IPv6 address because of stateless DHCPv6 network.
            host_name,  # Host name.
            name,  # Canonical hostname in the format 'hostname[.domain]'.
        )
        """
        v6_nets = dict((subnet.id, subnet) for subnet in
                       self.network.subnets if subnet.ip_version == 6)
        for port in self.network.ports:
            for alloc in port.fixed_ips:
                # Note(scollins) Only create entries that are
                # associated with the subnet being managed by this
                # dhcp agent
                if alloc.subnet_id in v6_nets:
                    addr_mode = v6_nets[alloc.subnet_id].ipv6_address_mode
                    if addr_mode == constants.IPV6_SLAAC:
                        continue
                    elif addr_mode == constants.DHCPV6_STATELESS:
                        alloc = hostname = fqdn = None
                        yield (port, alloc, hostname, fqdn)
                        continue

                hostname = 'host-%s' % alloc.ip_address.replace(
                    '.', '-').replace(':', '-')
                fqdn = hostname
                if self.conf.dhcp_domain:
                    fqdn = '%s.%s' % (fqdn, self.conf.dhcp_domain)
                yield (port, alloc, hostname, fqdn)

    def _get_port_extra_dhcp_opts(self, port):
        return getattr(port, edo_ext.EXTRADHCPOPTS, False)

    def _output_init_lease_file(self):
        """Write a fake lease file to bootstrap dnsmasq.

        The generated file is passed to the --dhcp-leasefile option of dnsmasq.
        This is used as a bootstrapping mechanism to avoid NAKing active leases
        when a dhcp server is scheduled to another agent. Using a leasefile
        will also prevent dnsmasq from NAKing or ignoring renewals after a
        restart.

        Format is as follows:
        epoch-timestamp mac_addr ip_addr hostname client-ID
        """
        filename = self.get_conf_file_name('leases')
        buf = six.StringIO()

        LOG.debug('Building initial lease file: %s', filename)
        # we make up a lease time for the database entry
        if self.conf.dhcp_lease_duration == -1:
            # Even with an infinite lease, a client may choose to renew a
            # previous lease on reboot or interface bounce so we should have
            # an entry for it.
            # Dnsmasq timestamp format for an infinite lease is  is 0.
            timestamp = 0
        else:
            timestamp = int(time.time()) + self.conf.dhcp_lease_duration
        dhcp_enabled_subnet_ids = [s.id for s in self.network.subnets
                                   if s.enable_dhcp]
        for (port, alloc, hostname, name) in self._iter_hosts():
            # don't write ip address which belongs to a dhcp disabled subnet.
            if not alloc or alloc.subnet_id not in dhcp_enabled_subnet_ids:
                continue

            ip_address = self._format_address_for_dnsmasq(alloc.ip_address)
            # all that matters is the mac address and IP. the hostname and
            # client ID will be overwritten on the next renewal.
            buf.write('%s %s %s * *\n' %
                      (timestamp, port.mac_address, ip_address))
        contents = buf.getvalue()
        utils.replace_file(filename, contents)
        LOG.debug('Done building initial lease file %s with contents:\n%s',
                  filename, contents)
        return filename

    @staticmethod
    def _format_address_for_dnsmasq(address):
        # (dzyu) Check if it is legal ipv6 address, if so, need wrap
        # it with '[]' to let dnsmasq to distinguish MAC address from
        # IPv6 address.
        if netaddr.valid_ipv6(address):
            return '[%s]' % address
        return address

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

        LOG.debug('Building host file: %s', filename)
        dhcp_enabled_subnet_ids = [s.id for s in self.network.subnets
                                   if s.enable_dhcp]
        # NOTE(ihrachyshka): the loop should not log anything inside it, to
        # avoid potential performance drop when lots of hosts are dumped
        for (port, alloc, hostname, name) in self._iter_hosts():
            if not alloc:
                if self._get_port_extra_dhcp_opts(port):
                    buf.write('%s,%s%s\n' %
                              (port.mac_address, 'set:', port.id))
                continue

            # don't write ip address which belongs to a dhcp disabled subnet.
            if alloc.subnet_id not in dhcp_enabled_subnet_ids:
                continue

            ip_address = self._format_address_for_dnsmasq(alloc.ip_address)

            if self._get_port_extra_dhcp_opts(port):
                client_id = self._get_client_id(port)
                if client_id and len(port.extra_dhcp_opts) > 1:
                    buf.write('%s,%s%s,%s,%s,%s%s\n' %
                              (port.mac_address, self._ID, client_id, name,
                               ip_address, 'set:', port.id))
                elif client_id and len(port.extra_dhcp_opts) == 1:
                    buf.write('%s,%s%s,%s,%s\n' %
                          (port.mac_address, self._ID, client_id, name,
                           ip_address))
                else:
                    buf.write('%s,%s,%s,%s%s\n' %
                              (port.mac_address, name, ip_address,
                               'set:', port.id))
            else:
                buf.write('%s,%s,%s\n' %
                          (port.mac_address, name, ip_address))

        utils.replace_file(filename, buf.getvalue())
        LOG.debug('Done building host file %s with contents:\n%s', filename,
                  buf.getvalue())
        return filename

    def _get_client_id(self, port):
        if self._get_port_extra_dhcp_opts(port):
            for opt in port.extra_dhcp_opts:
                if opt.opt_name == edo_ext.CLIENT_ID:
                    return opt.opt_value

    def _read_hosts_file_leases(self, filename):
        leases = set()
        try:
            with open(filename) as f:
                for l in f.readlines():
                    host = l.strip().split(',')
                    mac = host[0]
                    client_id = None
                    if host[1].startswith(self._ID):
                        ip = host[3].strip('[]')
                        client_id = host[1][len(self._ID):]
                    else:
                        ip = host[2].strip('[]')
                    leases.add((ip, mac, client_id))
        except (OSError, IOError):
            LOG.debug('Error while reading hosts file %s', filename)
        return leases

    def _release_unused_leases(self):
        filename = self.get_conf_file_name('host')
        old_leases = self._read_hosts_file_leases(filename)

        new_leases = set()
        for port in self.network.ports:
            client_id = self._get_client_id(port)
            for alloc in port.fixed_ips:
                new_leases.add((alloc.ip_address, port.mac_address, client_id))

        for ip, mac, client_id in old_leases - new_leases:
            self._release_lease(mac, ip, client_id)

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
            if alloc:
                buf.write('%s\t%s %s\n' % (alloc.ip_address, fqdn, hostname))
        addn_hosts = self.get_conf_file_name('addn_hosts')
        utils.replace_file(addn_hosts, buf.getvalue())
        return addn_hosts

    def _output_opts_file(self):
        """Write a dnsmasq compatible options file."""
        options, subnet_index_map = self._generate_opts_per_subnet()
        options += self._generate_opts_per_port(subnet_index_map)

        name = self.get_conf_file_name('opts')
        utils.replace_file(name, '\n'.join(options))
        return name

    def _generate_opts_per_subnet(self):
        options = []
        subnet_index_map = {}
        if self.conf.enable_isolated_metadata:
            subnet_to_interface_ip = self._make_subnet_interface_ip_map()
        isolated_subnets = self.get_isolated_subnets(self.network)
        for i, subnet in enumerate(self.network.subnets):
            if (not subnet.enable_dhcp or
                (subnet.ip_version == 6 and
                 getattr(subnet, 'ipv6_address_mode', None)
                 in [None, constants.IPV6_SLAAC])):
                continue
            if subnet.dns_nameservers:
                options.append(
                    self._format_option(
                        subnet.ip_version, i, 'dns-server',
                        ','.join(
                            Dnsmasq._convert_to_literal_addrs(
                                subnet.ip_version, subnet.dns_nameservers))))
            else:
                # use the dnsmasq ip as nameservers only if there is no
                # dns-server submitted by the server
                subnet_index_map[subnet.id] = i

            if self.conf.dhcp_domain and subnet.ip_version == 6:
                options.append('tag:tag%s,option6:domain-search,%s' %
                               (i, ''.join(self.conf.dhcp_domain)))

            gateway = subnet.gateway_ip
            host_routes = []
            for hr in subnet.host_routes:
                if hr.destination == constants.IPv4_ANY:
                    if not gateway:
                        gateway = hr.nexthop
                else:
                    host_routes.append("%s,%s" % (hr.destination, hr.nexthop))

            # Add host routes for isolated network segments

            if (isolated_subnets[subnet.id] and
                    self.conf.enable_isolated_metadata and
                    subnet.ip_version == 4):
                subnet_dhcp_ip = subnet_to_interface_ip[subnet.id]
                host_routes.append(
                    '%s/32,%s' % (METADATA_DEFAULT_IP, subnet_dhcp_ip)
                )
            elif not isolated_subnets[subnet.id] and gateway:
                host_routes.append(
                    '%s/32,%s' % (METADATA_DEFAULT_IP, gateway)
                )

            if subnet.ip_version == 4:
                host_routes.extend(["%s,0.0.0.0" % (s.cidr) for s in
                                    self.network.subnets
                                    if (s.ip_version == 4 and
                                        s.cidr != subnet.cidr)])

                if host_routes:
                    if gateway:
                        host_routes.append("%s,%s" % (constants.IPv4_ANY,
                                                      gateway))
                    options.append(
                        self._format_option(subnet.ip_version, i,
                                            'classless-static-route',
                                            ','.join(host_routes)))
                    options.append(
                        self._format_option(subnet.ip_version, i,
                                            WIN2k3_STATIC_DNS,
                                            ','.join(host_routes)))

                if gateway:
                    options.append(self._format_option(subnet.ip_version,
                                                       i, 'router',
                                                       gateway))
                else:
                    options.append(self._format_option(subnet.ip_version,
                                                       i, 'router'))
        return options, subnet_index_map

    def _generate_opts_per_port(self, subnet_index_map):
        options = []
        dhcp_ips = collections.defaultdict(list)
        for port in self.network.ports:
            if self._get_port_extra_dhcp_opts(port):
                port_ip_versions = set(
                    [netaddr.IPAddress(ip.ip_address).version
                     for ip in port.fixed_ips])
                for opt in port.extra_dhcp_opts:
                    if opt.opt_name == edo_ext.CLIENT_ID:
                        continue
                    opt_ip_version = opt.ip_version
                    if opt_ip_version in port_ip_versions:
                        options.append(
                            self._format_option(opt_ip_version, port.id,
                                                opt.opt_name, opt.opt_value))
                    else:
                        LOG.info(_LI("Cannot apply dhcp option %(opt)s "
                                     "because it's ip_version %(version)d "
                                     "is not in port's address IP versions"),
                                 {'opt': opt.opt_name,
                                  'version': opt_ip_version})

            # provides all dnsmasq ip as dns-server if there is more than
            # one dnsmasq for a subnet and there is no dns-server submitted
            # by the server
            if port.device_owner == constants.DEVICE_OWNER_DHCP:
                for ip in port.fixed_ips:
                    i = subnet_index_map.get(ip.subnet_id)
                    if i is None:
                        continue
                    dhcp_ips[i].append(ip.ip_address)

        for i, ips in dhcp_ips.items():
            for ip_version in (4, 6):
                vx_ips = [ip for ip in ips
                          if netaddr.IPAddress(ip).version == ip_version]
                if vx_ips:
                    options.append(
                        self._format_option(
                            ip_version, i, 'dns-server',
                            ','.join(
                                Dnsmasq._convert_to_literal_addrs(ip_version,
                                                                  vx_ips))))
        return options

    def _make_subnet_interface_ip_map(self):
        ip_dev = ip_lib.IPDevice(self.interface_name,
                                 namespace=self.network.namespace)

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

    def _format_option(self, ip_version, tag, option, *args):
        """Format DHCP option by option name or code."""
        option = str(option)
        pattern = "(tag:(.*),)?(.*)$"
        matches = re.match(pattern, option)
        extra_tag = matches.groups()[0]
        option = matches.groups()[2]

        if isinstance(tag, int):
            tag = self._TAG_PREFIX % tag

        if not option.isdigit():
            if ip_version == 4:
                option = 'option:%s' % option
            else:
                option = 'option6:%s' % option
        if extra_tag:
            tags = ('tag:' + tag, extra_tag[:-1], '%s' % option)
        else:
            tags = ('tag:' + tag, '%s' % option)
        return ','.join(tags + args)

    @staticmethod
    def _convert_to_literal_addrs(ip_version, ips):
        if ip_version == 4:
            return ips
        return ['[' + ip + ']' for ip in ips]

    @classmethod
    def get_isolated_subnets(cls, network):
        """Returns a dict indicating whether or not a subnet is isolated

        A subnet is considered non-isolated if there is a port connected to
        the subnet, and the port's ip address matches that of the subnet's
        gateway. The port must be owned by a nuetron router.
        """
        isolated_subnets = collections.defaultdict(lambda: True)
        subnets = dict((subnet.id, subnet) for subnet in network.subnets)

        for port in network.ports:
            if port.device_owner not in constants.ROUTER_INTERFACE_OWNERS:
                continue
            for alloc in port.fixed_ips:
                if subnets[alloc.subnet_id].gateway_ip == alloc.ip_address:
                    isolated_subnets[alloc.subnet_id] = False

        return isolated_subnets

    @classmethod
    def should_enable_metadata(cls, conf, network):
        """Determine whether the metadata proxy is needed for a network

        This method returns True for truly isolated networks (ie: not attached
        to a router), when the enable_isolated_metadata flag is True.

        This method also returns True when enable_metadata_network is True,
        and the network passed as a parameter has a subnet in the link-local
        CIDR, thus characterizing it as a "metadata" network. The metadata
        network is used by solutions which do not leverage the l3 agent for
        providing access to the metadata service via logical routers built
        with 3rd party backends.
        """
        if conf.enable_metadata_network and conf.enable_isolated_metadata:
            # check if the network has a metadata subnet
            meta_cidr = netaddr.IPNetwork(METADATA_DEFAULT_CIDR)
            if any(netaddr.IPNetwork(s.cidr) in meta_cidr
                   for s in network.subnets):
                return True

        if not conf.use_namespaces or not conf.enable_isolated_metadata:
            return False

        isolated_subnets = cls.get_isolated_subnets(network)
        return any(isolated_subnets[subnet.id] for subnet in network.subnets)


class DeviceManager(object):

    def __init__(self, conf, plugin):
        self.conf = conf
        self.plugin = plugin
        if not conf.interface_driver:
            LOG.error(_LE('An interface driver must be specified'))
            raise SystemExit(1)
        try:
            self.driver = importutils.import_object(
                conf.interface_driver, conf)
        except Exception as e:
            LOG.error(_LE("Error importing interface driver '%(driver)s': "
                          "%(inner)s"),
                      {'driver': conf.interface_driver,
                       'inner': e})
            raise SystemExit(1)

    def get_interface_name(self, network, port):
        """Return interface(device) name for use by the DHCP process."""
        return self.driver.get_device_name(port)

    def get_device_id(self, network):
        """Return a unique DHCP device ID for this host on the network."""
        # There could be more than one dhcp server per network, so create
        # a device id that combines host and network ids
        return commonutils.get_dhcp_agent_device_id(network.id, self.conf.host)

    def _set_default_route(self, network, device_name):
        """Sets the default gateway for this dhcp namespace.

        This method is idempotent and will only adjust the route if adjusting
        it would change it from what it already is.  This makes it safe to call
        and avoids unnecessary perturbation of the system.
        """
        device = ip_lib.IPDevice(device_name, namespace=network.namespace)
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
                LOG.debug('Setting gateway for dhcp netns on net %(n)s to '
                          '%(ip)s',
                          {'n': network.id, 'ip': subnet.gateway_ip})

                device.route.add_gateway(subnet.gateway_ip)

            return

        # No subnets on the network have a valid gateway.  Clean it up to avoid
        # confusion from seeing an invalid gateway here.
        if gateway is not None:
            LOG.debug('Removing gateway for dhcp netns on net %s', network.id)

            device.route.delete_gateway(gateway)

    def setup_dhcp_port(self, network):
        """Create/update DHCP port for the host if needed and return port."""

        device_id = self.get_device_id(network)
        subnets = {subnet.id: subnet for subnet in network.subnets
                   if subnet.enable_dhcp}

        dhcp_port = None
        for port in network.ports:
            port_device_id = getattr(port, 'device_id', None)
            if port_device_id == device_id:
                dhcp_enabled_subnet_ids = set(subnets)
                port_fixed_ips = []
                for fixed_ip in port.fixed_ips:
                    if fixed_ip.subnet_id in dhcp_enabled_subnet_ids:
                        port_fixed_ips.append(
                            {'subnet_id': fixed_ip.subnet_id,
                             'ip_address': fixed_ip.ip_address})

                port_subnet_ids = set(ip.subnet_id for ip in port.fixed_ips)
                # If there is a new dhcp enabled subnet or a port that is no
                # longer on a dhcp enabled subnet, we need to call update.
                if dhcp_enabled_subnet_ids != port_subnet_ids:
                    port_fixed_ips.extend(
                        dict(subnet_id=s)
                        for s in dhcp_enabled_subnet_ids - port_subnet_ids)
                    dhcp_port = self.plugin.update_dhcp_port(
                        port.id, {'port': {'network_id': network.id,
                                           'fixed_ips': port_fixed_ips}})
                    if not dhcp_port:
                        raise exceptions.Conflict()
                else:
                    dhcp_port = port
                # break since we found port that matches device_id
                break

        # check for a reserved DHCP port
        if dhcp_port is None:
            LOG.debug('DHCP port %(device_id)s on network %(network_id)s'
                      ' does not yet exist. Checking for a reserved port.',
                      {'device_id': device_id, 'network_id': network.id})
            for port in network.ports:
                port_device_id = getattr(port, 'device_id', None)
                if port_device_id == constants.DEVICE_ID_RESERVED_DHCP_PORT:
                    dhcp_port = self.plugin.update_dhcp_port(
                        port.id, {'port': {'network_id': network.id,
                                           'device_id': device_id}})
                    if dhcp_port:
                        break

        # DHCP port has not yet been created.
        if dhcp_port is None:
            LOG.debug('DHCP port %(device_id)s on network %(network_id)s'
                      ' does not yet exist.', {'device_id': device_id,
                                               'network_id': network.id})
            port_dict = dict(
                name='',
                admin_state_up=True,
                device_id=device_id,
                network_id=network.id,
                tenant_id=network.tenant_id,
                fixed_ips=[dict(subnet_id=s) for s in subnets])
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

    def setup(self, network):
        """Create and initialize a device for network's DHCP on this host."""
        port = self.setup_dhcp_port(network)
        interface_name = self.get_interface_name(network, port)

        if ip_lib.ensure_device_is_ready(interface_name,
                                         namespace=network.namespace):
            LOG.debug('Reusing existing device: %s.', interface_name)
        else:
            self.driver.plug(network.id,
                             port.id,
                             interface_name,
                             port.mac_address,
                             namespace=network.namespace)
            self.fill_dhcp_udp_checksums(namespace=network.namespace)
        ip_cidrs = []
        for fixed_ip in port.fixed_ips:
            subnet = fixed_ip.subnet
            if not ipv6_utils.is_auto_address_subnet(subnet):
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
            device = ip_lib.IPDevice(interface_name)
            device.route.pullup_route(interface_name,
                                      ip_version=constants.IP_VERSION_4)

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

    def fill_dhcp_udp_checksums(self, namespace):
        """Ensure DHCP reply packets always have correct UDP checksums."""
        iptables_mgr = iptables_manager.IptablesManager(use_ipv6=False,
                                                        namespace=namespace)
        ipv4_rule = ('-p udp --dport %d -j CHECKSUM --checksum-fill'
                     % constants.DHCP_RESPONSE_PORT)
        iptables_mgr.ipv4['mangle'].add_rule('POSTROUTING', ipv4_rule)
        iptables_mgr.apply()
