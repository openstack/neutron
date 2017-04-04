# Copyright 2015 Red Hat, Inc.
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

from oslo_log import log as logging
from oslo_utils import excutils

from neutron.agent.linux import async_process
from neutron.agent.linux import ip_lib

LOG = logging.getLogger(__name__)


class IPMonitorEvent(object):
    def __init__(self, line, added, interface, cidr):
        self.line = line
        self.added = added
        self.interface = interface
        self.cidr = cidr

    def __str__(self):
        return self.line

    @classmethod
    def from_text(cls, line):
        route = line.split()

        try:
            first_word = route[0]
        except IndexError:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to parse route "%s"', line)

        added = (first_word != 'Deleted')
        if not added:
            route = route[1:]

        try:
            interface = ip_lib.remove_interface_suffix(route[1])
            cidr = route[3]
        except IndexError:
            with excutils.save_and_reraise_exception():
                LOG.error('Unable to parse route "%s"', line)

        return cls(line, added, interface, cidr)


class IPMonitor(async_process.AsyncProcess):
    """Wrapper over `ip monitor address`.

    To monitor and react indefinitely:
        m = IPMonitor(namespace='tmp', root_as_root=True)
        m.start()
        for iterable in m:
            event = IPMonitorEvent.from_text(iterable)
            print(event, event.added, event.interface, event.cidr)
    """

    def __init__(self,
                 namespace=None,
                 run_as_root=True,
                 respawn_interval=None):
        super(IPMonitor, self).__init__(['ip', '-o', 'monitor', 'address'],
                                        run_as_root=run_as_root,
                                        respawn_interval=respawn_interval,
                                        namespace=namespace)

    def __iter__(self):
        return self.iter_stdout(block=True)

    def start(self):
        super(IPMonitor, self).start(block=True)

    def stop(self):
        super(IPMonitor, self).stop(block=True)
