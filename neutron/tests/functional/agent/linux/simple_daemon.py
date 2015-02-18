# Copyright 2014 Red Hat, Inc.
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

import time

from oslo_config import cfg

from neutron.agent.linux import daemon


def main():

    class SimpleDaemon(daemon.Daemon):
        """The purpose of this daemon is to serve as an example, and also as
        a dummy daemon, which can be invoked by functional testing, it
        does nothing but setting the pid file, and staying detached in the
        background.
        """

        def run(self):
            while True:
                time.sleep(10)

    opts = [
        cfg.StrOpt('uuid',
                   help=_('uuid provided from the command line '
                          'so external_process can track us via /proc/'
                          'cmdline interface.'),
                   required=True),
        cfg.StrOpt('pid_file',
                   help=_('Location of pid file of this process.'),
                   required=True)
    ]

    cfg.CONF.register_cli_opts(opts)
    # Don't get the default configuration file
    cfg.CONF(project='neutron', default_config_files=[])
    simple_daemon = SimpleDaemon(cfg.CONF.pid_file,
                                 uuid=cfg.CONF.uuid)
    simple_daemon.start()


if __name__ == "__main__":
    main()
