# Copyright 2016 Red Hat, Inc.
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

import os
import random
import signal
import socket
import sys
import time

from neutron_lib import constants as n_const
from oslo_config import cfg

from neutron.agent.linux import daemon

UNIX_FAMILY = 'UNIX'

OPTS = [
    cfg.IntOpt('num_children',
               short='n',
               default=0,
               help='Number of children to spawn',
               required=False),
    cfg.StrOpt('family',
               short='f',
               default=n_const.IPv4,
               choices=[n_const.IPv4, n_const.IPv6, UNIX_FAMILY],
               help='Listen socket family (%(v4)s, %(v6)s or %(unix)s)' %
                     {
                         'v4': n_const.IPv4,
                         'v6': n_const.IPv6,
                         'unix': UNIX_FAMILY
                     },
               required=False),
    cfg.StrOpt('proto',
               short='p',
               default=n_const.PROTO_NAME_TCP,
               choices=[n_const.PROTO_NAME_TCP, n_const.PROTO_NAME_UDP],
               help='Protocol (%(tcp)s or %(udp)s)' %
                     {
                         'tcp': n_const.PROTO_NAME_TCP,
                         'udp': n_const.PROTO_NAME_UDP
                     },
               required=False),
    cfg.BoolOpt('parent_listen',
               short='pl',
               default=True,
               help='Parent process must listen too',
               required=False),
    cfg.BoolOpt('ignore_sigterm',
                short='i',
                default=False,
                help='Ignore SIGTERM',
                required=False)
]


class ProcessSpawn(daemon.Daemon):
    """This class is part of the functional test of the netns_cleanup module.

    It allows spawning processes that listen on random ports either on
    tcp(6), udp(6) or unix sockets. Also it allows handling or ignoring
    SIGTERM to check whether the cleanup works as expected by getting rid
    of the spawned processes.
    """

    MAX_BIND_RETRIES = 64

    DCT_FAMILY = {
        n_const.IPv4: socket.AF_INET,
        n_const.IPv6: socket.AF_INET6,
        UNIX_FAMILY: socket.AF_UNIX
    }
    DCT_PROTO = {
        n_const.PROTO_NAME_TCP: socket.SOCK_STREAM,
        n_const.PROTO_NAME_UDP: socket.SOCK_DGRAM,
    }

    def __init__(self, pidfile=None,
                 family=n_const.IPv4,
                 proto=n_const.PROTO_NAME_TCP,
                 ignore_sigterm=False, num_children=0,
                 parent_must_listen=True):
        self.family = family
        self.proto = proto
        self.ignore_sigterm = ignore_sigterm
        self.num_children = num_children
        self.listen_socket = None
        self.parent_must_listen = parent_must_listen
        self.child_pids = []

        super(ProcessSpawn, self).__init__(pidfile)

    def start_listening(self):
        socket_family = self.DCT_FAMILY[self.family]
        socket_type = self.DCT_PROTO[self.proto]

        self.listen_socket = socket.socket(socket_family, socket_type)

        # Set a different seed per process to increase randomness
        random.seed(os.getpid())

        # Try to listen in a random port which is not currently in use
        retries = 0
        while retries < ProcessSpawn.MAX_BIND_RETRIES:
            # NOTE(dalvarez): not finding a free port on a freshly created
            # namespace is very unlikely but if problems show up, retries can
            # be increased to avoid tests failing
            try:
                if self.family == UNIX_FAMILY:
                    self.listen_socket.bind('')
                else:
                    # Pick a non privileged port
                    port = random.randint(1024, 65535)
                    self.listen_socket.bind(('', port))
            except socket.error:
                retries += 1
            else:
                if n_const.PROTO_NAME_TCP in self.proto:
                    self.listen_socket.listen(0)
                break

    def do_sleep(self):
        while True:
            time.sleep(10)

    def run(self):
        # Spawn as many children as requested
        children = []
        while len(children) != self.num_children:
            child_pid = os.fork()
            if child_pid == 0:
                # Listen and do nothing else
                self.start_listening()
                self.do_sleep()
                return
            children.append(child_pid)

        # Install a SIGTERM handler if requested
        handler = (
            signal.SIG_IGN if self.ignore_sigterm else self.sigterm_handler)
        signal.signal(signal.SIGTERM, handler)

        self.child_pids = children
        if self.parent_must_listen:
            self.start_listening()
        self.do_sleep()

    def sigterm_handler(self, signum, frame):
        if self.listen_socket:
            self.listen_socket.close()
        for child in self.child_pids:
            try:
                os.kill(child, signal.SIGTERM)
            except OSError:
                pass
        sys.exit(0)


def main():
    cfg.CONF.register_cli_opts(OPTS)
    cfg.CONF(project='neutron', default_config_files=[])
    proc_spawn = ProcessSpawn(num_children=cfg.CONF.num_children,
                      family=cfg.CONF.family,
                      proto=cfg.CONF.proto,
                      parent_must_listen=cfg.CONF.parent_listen,
                      ignore_sigterm=cfg.CONF.ignore_sigterm)
    proc_spawn.start()


if __name__ == "__main__":
    main()
