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

from quantum.agent.linux import utils


class IPDevice(object):
    def __init__(self, name, root_helper=None):
        self.name = name
        self.root_helper = root_helper
        self._commands = {}

        self.link = IpLinkCommand(self)
        self.tuntap = IpTuntapCommand(self)
        self.addr = IpAddrCommand(self)

    def __eq__(self, other):
        return self.name == other.name

    @classmethod
    def _execute(cls, options, command, args, root_helper=None):
        opt_list = ['-%s' % o for o in options]
        return utils.execute(['ip'] + opt_list + [command] + list(args),
                             root_helper=root_helper)

    @classmethod
    def get_devices(cls):
        retval = []
        for line in cls._execute('o', 'link', ('list',)).split('\n'):
            if '<' not in line:
                continue
            index, name, attrs = line.split(':', 2)
            retval.append(IPDevice(name.strip()))
        return retval


class IpCommandBase(object):
    COMMAND = ''

    def __init__(self, parent):
        self._parent = parent

    @property
    def name(self):
        return self._parent.name

    def _run(self, *args, **kwargs):
        return self._parent._execute(kwargs.get('options', []),
                                     self.COMMAND,
                                     args)

    def _as_root(self, *args, **kwargs):
        if not self._parent.root_helper:
            raise exceptions.SudoRequired()
        return self._parent._execute(kwargs.get('options', []),
                                     self.COMMAND,
                                     args,
                                     self._parent.root_helper)


class IpLinkCommand(IpCommandBase):
    COMMAND = 'link'

    def set_address(self, mac_address):
        self._as_root('set', self.name, 'address', mac_address)

    def set_mtu(self, mtu_size):
        self._as_root('set', self.name, 'mtu', mtu_size)

    def set_up(self):
        self._as_root('set', self.name, 'up')

    def set_down(self):
        self._as_root('set', self.name, 'down')

    def delete(self):
        self._as_root('delete', self.name)

    @property
    def address(self):
        return self.attributes.get('link/ether')

    @property
    def state(self):
        return self.attributes.get('state')

    @property
    def mtu(self):
        return self.attributes.get('mtu')

    @property
    def qdisc(self):
        return self.attributes.get('qdisc')

    @property
    def qlen(self):
        return self.attributes.get('qlen')

    @property
    def attributes(self):
        return self._parse_line(self._run('show', self.name, options='o'))

    def _parse_line(self, value):
        device_name, settings = value.replace("\\", '').split('>', 1)

        tokens = settings.split()
        keys = tokens[::2]
        values = [int(v) if v.isdigit() else v for v in tokens[1::2]]

        retval = dict(zip(keys, values))
        return retval


class IpTuntapCommand(IpCommandBase):
    COMMAND = 'tuntap'

    def add(self):
        self._as_root('add', self.name, 'mode', 'tap')


class IpAddrCommand(IpCommandBase):
    COMMAND = 'addr'

    def add(self, ip_version, cidr, broadcast, scope='global'):
        self._as_root('add',
                      cidr,
                      'brd',
                      broadcast,
                      'scope',
                      scope,
                      'dev',
                      self.name,
                      options=[ip_version])

    def delete(self, ip_version, cidr):
        self._as_root('del',
                      cidr,
                      'dev',
                      self.name,
                      options=[ip_version])

    def flush(self):
        self._as_root('flush', self.name)

    def list(self, scope=None, to=None, filters=[]):
        retval = []

        if scope:
            filters += ['scope', scope]
        if to:
            filters += ['to', to]

        for line in self._run('show', self.name, *filters).split('\n'):
            line = line.strip()
            if not line.startswith('inet'):
                continue
            parts = line.split()
            if parts[0] == 'inet6':
                version = 6
                scope = parts[3]
            else:
                version = 4
                scope = parts[5]

            retval.append(dict(cidr=parts[1],
                               scope=scope,
                               ip_version=version,
                               dynamic=('dynamic' == parts[-1])))
        return retval


def device_exists(device_name):
    try:
        address = IPDevice(device_name).link.address
    except RuntimeError:
        return False

    return True
