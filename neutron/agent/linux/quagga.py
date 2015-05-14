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
import stat

import netaddr
from oslo.config import cfg

from neutron.agent.linux import external_process
from neutron.agent.linux import utils
from neutron.common import exceptions
from neutron.openstack.common.gettextutils import _LW
from neutron.openstack.common import log as logging


OPTS = [
    cfg.StrOpt('zebra_bin',
               default='/usr/lib/quagga/zebra',
               help=_('Path to Zebra binary')),
    cfg.StrOpt('zebra_config',
               default='/etc/quagga/zebra.conf',
               help=_('Path to Zebra configuration file')),

    cfg.StrOpt('ospfd_bin',
               default='/usr/lib/quagga/ospfd',
               help=_('Path to OSPFd binary')),

    cfg.StrOpt('ospfd_config',
               default='/etc/quagga/ospfd.conf',
               help=_('Path to OSPFd configuration file')),
]



LOG = logging.getLogger(__name__)


class QuaggaProcess(object):
    """A generic class to control individual Quagga process
    """
    def __init__(self, resource_id, binary_path, config_path
                 namespace=None, root_helper=None, enable_vty=False):
        self.resource_id = resource_id
        self.binary_path = binary
        self.config_path =  config_path
        self.namespace = namespace
        self.root_helper = root_helper
        self.temp_path = '/tmp'

        self._spawned = False


    def spawn(self):
        self._process = self.get_process(cfg.CONF,
                                        self.resource_id,
                                        self.root_helper,
                                        self.namespace,
                                        self.temp_path)

        def callback(pid_file):
            cmd = [self.binary_path,
                   '-f', self.config_path,
                   '-p', pid_file]
            if self.enable_vty:
                cmd += ['-A', self._get_vty_path()]
            return cmd

        self._process.enable(callback, reload_cfg=True)

        self.spawned = True
        LOG.debug('Quagga process %s spawned with config %s', self.resource_id, config_path)

    def _get_vty_path(self):
        return os.path.join((
            self.temp_path,
            ''.join((self.resource_id, str(self.namespace), '.vty'))
        ))


    def spawn_or_restart(self):
        if self._process:
            self.restart()
        else:
            self.spawn()

    def restart(self):
        if self._process.active:
            self._process.reload_cfg()
        else:
            LOG.warn(_LW('A previous instance of Quagga process %s seems to be dead, '
                         'unable to restart it, a new instance will be '
                         'spawned'), self.resource_id)
            self._process.disable()
            self.spawn()

    def disable(self):
        if self._process:
            self._process.disable(sig='15')
            self.spawned = False

    def revive(self):
        if self.spawned and not self._process.active:
            self.restart()

    @classmethod
    def _get_process(cls, conf, resource_id, root_helper, namespace, conf_path):
        return external_process.ProcessManager(
            conf,
            resource_id,
            root_helper,
            namespace,
            pids_path=conf_path)

    @property
    def spawned(self):
        return self._spawned

    def configure(self, commands):
        """Pushes configuration to a Quagga service instance"""
        raise NotImplementedError()


class QuaggaRouter(object):
    """Responsible for
    - translation of Neutron router events into Quagga services configuration
    - managing the lifecycle of relevant Quagga processes
    """
    def __init__(self, router_info):
        CONF = cfg.CONF
        namespace = router_info.ns_name
        root_helper = router_info.root_helper

        self.zebra = QuaggaProcess('zebra', CONF.zebra_bin, CONF.zebra_config, namespace, root_helper)
        self.ospfd = QuaggaProcess('ospfd', CONF.ospfd_bin, CONF.ospfd_config, namespace, root_helper, enable_vty=True)

    def spawn(self):
        self.zebra.spawn()
        self.ospfd.spawn()

    def disable(self):
        self.ospfd.disable()
        self.zebra.disable()


    def add_port(self, router_info, port, interface_name):
        raise NotImplementedError()

    def delete_port(self, router_info, port, interface_name):
        raise NotImplementedError()

    @classmethod
    def get_router_id(cls, router_info):
        """Given a RouterInfo instance returns a hashable object
        unambiguously indentifying a particluar Neutron router"""
        raise NotImplementedError()



class QuaggaManager(object):
    """Aggregated class to control all the Quagga services running on the machine.
    Responsible for
    - lifecycle management for virtual router instances (QuaggaRouter)
    - dispatching Neutron router events to a corresponding QuaggaRouter intstance
    """

    def __init__(self):
        self._routers = dict()

    def add_router(self, router_info):
        router_id = QuaggaRouter.get_router_id(router_info)
        router = QuaggaRouter(router_info)

        router = self._routers[router_id] = QuaggaRouter(router_info)
        router.spawn()


    def add_router_port(self, router_info, port, interface_name):
        router_id = QuaggaRouter.get_router_id(router_info)
        router = self._routers[router_id]

        router.add_port(router_info, port, interface_name)

    def delete_router_port(self, router_info, port, interface_name):
        router_id = QuaggaRouter.get_router_id(router_info)
        router = self._routers[router_id]

        router.delete_port(router_info, port, interface_name)


    def delete_router(self, router_info):
        router_id = QuaggaRouter.get_router_id(router_info)
        router = self._routers[router_id]

        router.disable()
        del self._routers[router_id]
