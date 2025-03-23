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
import shutil
import signal

import fixtures
import psutil
import tenacity

from neutron.agent.linux import utils


def _kill_process_if_exists(command: str) -> None:
    _pid = utils.pgrep(command)
    if _pid:
        utils.kill_process(_pid, signal.SIGKILL)


class DaemonProcessFixture(fixtures.Fixture):
    def __init__(self, temp_dir):
        super().__init__()
        self.temp_dir = temp_dir

    def _get_pid_from_pidfile(self, pidfile):
        with open(os.path.join(self.temp_dir, pidfile)) as pidfile_f:
            pid = pidfile_f.read().strip()
            try:
                return int(pid)
            except ValueError:
                raise RuntimeError(
                    "Pidfile %(pidfile)s contains %(pid)s that "
                    "is not a pid" % {'pidfile': pidfile, 'pid': pid}
                )


class OvnNorthd(DaemonProcessFixture):

    def __init__(self, temp_dir, ovn_nb_db, ovn_sb_db, protocol='unix',
                 debug=True):
        super().__init__(temp_dir)
        self.ovn_nb_db = ovn_nb_db
        self.ovn_sb_db = ovn_sb_db
        self.protocol = protocol
        self.unixctl_path = os.path.join(self.temp_dir, 'ovn_northd.ctl')
        self.log_file_path = os.path.join(self.temp_dir, 'ovn_northd.log')
        self.debug = debug
        if self.protocol == 'ssl':
            self.private_key = os.path.join(self.temp_dir, 'ovn-privkey.pem')
            self.certificate = os.path.join(self.temp_dir, 'ovn-cert.pem')
            self.ca_cert = os.path.join(self.temp_dir, 'controllerca',
                                        'cacert.pem')

    def _setUp(self):
        self.addCleanup(self.stop)
        self.start()

    def start(self):
        # start the ovn-northd
        ovn_northd_cmd = [
            shutil.which('ovn-northd'), '-vconsole:off',
            '--detach',
            '--ovnnb-db=%s' % self.ovn_nb_db,
            '--ovnsb-db=%s' % self.ovn_sb_db,
            '--no-chdir',
            '--unixctl=%s' % self.unixctl_path,
            '--log-file=%s' % (self.log_file_path)]
        if self.protocol == 'ssl':
            ovn_northd_cmd.append('--private-key=%s' % self.private_key)
            ovn_northd_cmd.append('--certificate=%s' % self.certificate)
            ovn_northd_cmd.append('--ca-cert=%s' % self.ca_cert)
        if self.debug:
            ovn_northd_cmd.append('--verbose')
        obj, _ = utils.create_process(ovn_northd_cmd)
        obj.communicate()

    def stop(self):
        try:
            if os.path.exists(self.unixctl_path):
                stop_cmd = ['ovs-appctl', '-t', self.unixctl_path, 'exit']
                utils.execute(stop_cmd)
        except Exception:
            _kill_process_if_exists(self.unixctl_path)


class OvsdbServer(DaemonProcessFixture):

    def __init__(self, temp_dir, ovs_dir, ovn_nb_db=True, ovn_sb_db=False,
                 protocol='unix', debug=True):
        super().__init__(temp_dir)
        self.ovs_dir = ovs_dir
        self.ovn_nb_db = ovn_nb_db
        self.ovn_sb_db = ovn_sb_db
        # The value of the protocol must be unix or tcp or ssl
        self.protocol = protocol
        self.ovsdb_server_processes = []
        self.private_key = os.path.join(self.temp_dir, 'ovn-privkey.pem')
        self.certificate = os.path.join(self.temp_dir, 'ovn-cert.pem')
        self.ca_cert = os.path.join(self.temp_dir, 'controllerca',
                                    'cacert.pem')
        self.debug = debug

    def _setUp(self):
        if self.ovn_nb_db:
            self.ovsdb_server_processes.append(
                {'db_path': os.path.join(self.temp_dir, 'ovn_nb.db'),
                 'schema_path': os.path.join(self.ovs_dir, 'ovn-nb.ovsschema'),
                 'remote_path': os.path.join(self.temp_dir, 'ovnnb_db.sock'),
                 'protocol': self.protocol,
                 'remote_ip': '127.0.0.1',
                 'remote_port': '0',
                 'pidfile': 'ovn-nb.pid',
                 'unixctl_path': os.path.join(self.temp_dir, 'ovnnb_db.ctl'),
                 'log_file_path': os.path.join(self.temp_dir, 'ovn_nb.log'),
                 'db_type': 'nb',
                 'connection': 'db:OVN_Northbound,NB_Global,connections',
                 'ctl_cmd': 'ovn-nbctl'})

        if self.ovn_sb_db:
            self.ovsdb_server_processes.append(
                {'db_path': os.path.join(self.temp_dir, 'ovn_sb.db'),
                 'schema_path': os.path.join(self.ovs_dir, 'ovn-sb.ovsschema'),
                 'remote_path': os.path.join(self.temp_dir, 'ovnsb_db.sock'),
                 'protocol': self.protocol,
                 'remote_ip': '127.0.0.1',
                 'remote_port': '0',
                 'pidfile': 'ovn-sb.pid',
                 'unixctl_path': os.path.join(self.temp_dir, 'ovnsb_db.ctl'),
                 'log_file_path': os.path.join(self.temp_dir, 'ovn_sb.log'),
                 'db_type': 'sb',
                 'connection': 'db:OVN_Southbound,SB_Global,connections',
                 'ctl_cmd': 'ovn-sbctl'})
        self.addCleanup(self.stop)
        self.start()

    def _init_ovsdb_pki(self):
        os.chdir(self.temp_dir)
        pki_init_cmd = [shutil.which('ovs-pki'), 'init',
                        '-d', self.temp_dir, '-l',
                        os.path.join(self.temp_dir, 'pki.log'), '--force']
        utils.execute(pki_init_cmd)
        pki_req_sign = [shutil.which('ovs-pki'), 'req+sign', 'ovn',
                        'controller', '-d', self.temp_dir, '-l',
                        os.path.join(self.temp_dir, 'pki.log'), '--force']
        utils.execute(pki_req_sign)

    def delete_dbs(self):
        for ovsdb in self.ovsdb_server_processes:
            try:
                os.remove(ovsdb['db_path'])
            except OSError:
                pass

    def start(self):
        pki_done = False
        for ovsdb_process in self.ovsdb_server_processes:
            # Create the db from the schema using ovsdb-tool only if the file
            # is not present. It could be possible to restart the ovsdb-server
            # using an existing database file.
            if not os.path.exists(ovsdb_process['db_path']):
                ovsdb_tool_cmd = [shutil.which('ovsdb-tool'),
                                  'create', ovsdb_process['db_path'],
                                  ovsdb_process['schema_path']]
                utils.execute(ovsdb_tool_cmd)

            # start the ovsdb-server
            ovsdb_server_cmd = [
                shutil.which('ovsdb-server'), '-vconsole:off',
                '--detach',
                '--pidfile=%s' % os.path.join(
                    self.temp_dir, ovsdb_process['pidfile']),
                '--log-file=%s' % (ovsdb_process['log_file_path']),
                '--remote=punix:%s' % (ovsdb_process['remote_path']),
                '--remote=%s' % (ovsdb_process['connection']),
                '--unixctl=%s' % (ovsdb_process['unixctl_path']),
                '--detach']
            if ovsdb_process['protocol'] == 'ssl':
                if not pki_done:
                    pki_done = True
                    self._init_ovsdb_pki()
                ovsdb_server_cmd.append('--private-key=%s' % self.private_key)
                ovsdb_server_cmd.append('--certificate=%s' % self.certificate)
                ovsdb_server_cmd.append('--ca-cert=%s' % self.ca_cert)
            ovsdb_server_cmd.append(ovsdb_process['db_path'])
            if self.debug:
                ovsdb_server_cmd.append('--verbose')
            obj, _ = utils.create_process(ovsdb_server_cmd)
            obj.communicate()

            conn_cmd = [shutil.which(ovsdb_process['ctl_cmd']),
                        '--db=unix:%s' % ovsdb_process['remote_path'],
                        'set-connection',
                        'p{}:{}:{}'.format(ovsdb_process['protocol'],
                                           ovsdb_process['remote_port'],
                                           ovsdb_process['remote_ip']),
                        '--', 'set', 'connection', '.',
                        'inactivity_probe=60000']

            @tenacity.retry(wait=tenacity.wait_exponential(multiplier=0.1),
                            stop=tenacity.stop_after_delay(3), reraise=True)
            def _set_connection():
                utils.execute(conn_cmd)

            @tenacity.retry(
                wait=tenacity.wait_exponential(multiplier=0.1),
                stop=tenacity.stop_after_delay(10),
                reraise=True)
            def get_ovsdb_remote_port_retry(pid):
                process = psutil.Process(pid)
                for connect in process.net_connections():
                    if connect.status == 'LISTEN':
                        return connect.laddr[1]
                raise Exception("Could not find LISTEN port.")

            if ovsdb_process['protocol'] != 'unix':
                _set_connection()
                pid = self._get_pid_from_pidfile(ovsdb_process['pidfile'])
                ovsdb_process['remote_port'] = \
                    get_ovsdb_remote_port_retry(pid)

    def stop(self):
        for ovsdb_process in self.ovsdb_server_processes:
            try:
                stop_cmd = ['ovs-appctl', '-t', ovsdb_process['unixctl_path'],
                            'exit']
                utils.execute(stop_cmd)
            except Exception:
                _kill_process_if_exists(ovsdb_process['unixctl_path'])

    def get_ovsdb_connection_path(self, db_type='nb'):
        for ovsdb_process in self.ovsdb_server_processes:
            if ovsdb_process['db_type'] == db_type:
                if ovsdb_process['protocol'] == 'unix':
                    return 'unix:' + ovsdb_process['remote_path']
                return '{}:{}:{}'.format(ovsdb_process['protocol'],
                                         ovsdb_process['remote_ip'],
                                         ovsdb_process['remote_port'])
