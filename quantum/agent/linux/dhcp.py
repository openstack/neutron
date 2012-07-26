# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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
import logging
import os
import re
import StringIO
import tempfile

import netaddr

from quantum.agent.linux import utils
from quantum.openstack.common import cfg
from quantum.openstack.common import importutils

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt('dhcp_confs',
               default='$state_path/dhcp',
               help='Location to store DHCP server config files'),
    cfg.IntOpt('dhcp_lease_time',
               default=120,
               help='Lifetime of a DHCP lease in seconds'),
    cfg.StrOpt('dhcp_domain',
               default='openstacklocal',
               help='Domain to use for building the hostnames'),
    cfg.StrOpt('dnsmasq_config_file',
               help='Override the default dnsmasq settings with this file'),
    cfg.StrOpt('dnsmasq_dns_server',
               help='Use another DNS server before any in /etc/resolv.conf.'),
]

IPV4 = 4
IPV6 = 6
UDP = 'udp'
TCP = 'tcp'
DNS_PORT = 53
DHCPV4_PORT = 67
DHCPV6_PORT = 467


class DhcpBase(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, conf, network, root_helper='sudo',
                 device_delegate=None):
        self.conf = conf
        self.network = network
        self.root_helper = root_helper
        self.device_delegate = device_delegate

    @abc.abstractmethod
    def enable(self):
        """Enables DHCP for this network."""

    @abc.abstractmethod
    def disable(self):
        """Disable dhcp for this network."""

    def restart(self):
        """Restart the dhcp service for the network."""
        self.disable()
        self.enable()

    @abc.abstractproperty
    def active(self):
        """Boolean representing the running state of the DHCP server."""

    @abc.abstractmethod
    def reload_allocations(self):
        """Force the DHCP server to reload the assignment database."""


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
        if self.active:
            self.reload_allocations()
        elif self._enable_dhcp():
            self.device_delegate.setup(self.network, reuse_existing=True)
            self.spawn_process()

    def disable(self):
        """Disable DHCP for this network by killing the local process."""
        pid = self.pid

        if self.active:
            utils.execute(['kill', '-9', pid], self.root_helper)
            self.device_delegate.destroy(self.network)
        elif pid:
            LOG.debug(_('DHCP for %s pid %d is stale, ignoring command') %
                      (self.network.id, pid))
        else:
            LOG.debug(_('No DHCP started for %s') % self.network.id)

    def get_conf_file_name(self, kind, ensure_conf_dir=False):
        """Returns the file name for a given kind of config file."""
        confs_dir = os.path.abspath(os.path.normpath(self.conf.dhcp_confs))
        conf_dir = os.path.join(confs_dir, self.network.id)
        if ensure_conf_dir:
            if not os.path.isdir(conf_dir):
                os.makedirs(conf_dir, 0755)

        return os.path.join(conf_dir, kind)

    def _get_value_from_conf_file(self, kind, converter=None):
        """A helper function to read a value from one of the state files."""
        file_name = self.get_conf_file_name(kind)
        msg = _('Error while reading %s')

        try:
            with open(file_name, 'r') as f:
                try:
                    return converter and converter(f.read()) or f.read()
                except ValueError, e:
                    msg = _('Unable to convert value in %s')
        except IOError, e:
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
        cmd = ['cat', '/proc/%s/cmdline' % pid]
        try:
            return self.network.id in utils.execute(cmd, self.root_helper)
        except RuntimeError, e:
            return False

    @abc.abstractmethod
    def spawn_process(self):
        pass


class Dnsmasq(DhcpLocalProcess):
    # The ports that need to be opened when security policies are active
    # on the Quantum port used for DHCP.  These are provided as a convenience
    # for users of this class.
    PORTS = {IPV4: [(UDP, DNS_PORT), (TCP, DNS_PORT), (UDP, DHCPV4_PORT)],
             IPV6: [(UDP, DNS_PORT), (TCP, DNS_PORT), (UDP, DHCPV6_PORT)],
             }

    _TAG_PREFIX = 'tag%d'

    def spawn_process(self):
        """Spawns a Dnsmasq process for the network."""
        interface_name = self.device_delegate.get_interface_name(self.network)
        cmd = [
            'NETWORK_ID=%s' % self.network.id,
            # TODO (mark): this is dhcpbridge script we'll need to know
            # when an IP address has been released
            'dnsmasq',
            '--no-hosts',
            '--no-resolv',
            '--strict-order',
            '--bind-interfaces',
            '--interface=%s' % interface_name,
            '--except-interface=lo',
            '--domain=%s' % self.conf.dhcp_domain,
            '--pid-file=%s' % self.get_conf_file_name('pid',
                                                      ensure_conf_dir=True),
            #TODO (mark): calculate value from cidr (defaults to 150)
            #'--dhcp-lease-max=%s' % ?,
            '--dhcp-hostsfile=%s' % self._output_hosts_file(),
            '--dhcp-optsfile=%s' % self._output_opts_file(),
            '--leasefile-ro',
        ]

        for i, subnet in enumerate(self.network.subnets):
            # if a subnet is specified to have dhcp disabled
            if not subnet.enable_dhcp:
                continue
            if subnet.ip_version == 4:
                mode = 'static'
            else:
                # TODO (mark): how do we indicate other options
                # ra-only, slaac, ra-nameservers, and ra-stateless.
                mode = 'static'
            cmd.append('--dhcp-range=set:%s,%s,%s,%ss' %
                       (self._TAG_PREFIX % i,
                        netaddr.IPNetwork(subnet.cidr).network,
                        mode,
                        self.conf.dhcp_lease_time))

        if self.conf.dnsmasq_config_file:
            cmd.append('--conf-file=%s' % self.conf.dnsmasq_config_file)
        if self.conf.dnsmasq_dns_server:
            cmd.append('--server=%s' % self.conf.dnsmasq_dns_server)

        utils.execute(cmd, self.root_helper)

    def reload_allocations(self):
        """If all subnets turn off dhcp, kill the process."""
        if not self._enable_dhcp():
            self.disable()
            LOG.debug(_('Killing dhcpmasq for network since all subnets have \
                         turned off DHCP: %s') % self.network.id)
            return

        """Rebuilds the dnsmasq config and signal the dnsmasq to reload."""
        self._output_hosts_file()
        self._output_opts_file()
        utils.execute(['kill', '-HUP', self.pid], self.root_helper)
        LOG.debug(_('Reloading allocations for network: %s') % self.network.id)

    def _output_hosts_file(self):
        """Writes a dnsmasq compatible hosts file."""
        r = re.compile('[:.]')
        buf = StringIO.StringIO()

        for port in self.network.ports:
            for alloc in port.fixed_ips:
                name = '%s.%s' % (r.sub('-', alloc.ip_address),
                                  self.conf.dhcp_domain)
                buf.write('%s,%s,%s\n' %
                          (port.mac_address, name, alloc.ip_address))

        name = self.get_conf_file_name('host')
        replace_file(name, buf.getvalue())
        return name

    def _output_opts_file(self):
        """Write a dnsmasq compatible options file."""
        # TODO (mark): add support for nameservers
        options = []
        for i, subnet in enumerate(self.network.subnets):
            if not subnet.enable_dhcp:
                continue
            elif subnet.ip_version == 6:
                continue
            else:
                #NOTE(xchenum) need to handle no gw case
                options.append((self._TAG_PREFIX % i,
                                'option',
                                'router',
                                subnet.gateway_ip))

        name = self.get_conf_file_name('opts')
        replace_file(name, '\n'.join(['tag:%s,%s:%s,%s' % o for o in options]))
        return name


def replace_file(file_name, data):
    """Replaces the contents of file_name with data in a safe manner.

    First write to a temp file and then rename. Since POSIX renames are
    atomic, the file is unlikely to be corrupted by competing writes.

    We create the tempfile on the same device to ensure that it can be renamed.
    """

    base_dir = os.path.dirname(os.path.abspath(file_name))
    tmp_file = tempfile.NamedTemporaryFile('w+', dir=base_dir, delete=False)
    tmp_file.write(data)
    tmp_file.close()
    os.chmod(tmp_file.name, 0644)
    os.rename(tmp_file.name, file_name)
