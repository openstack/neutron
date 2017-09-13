# Copyright 2016 Red Hat, Inc.
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
import errno
import socket
import time

from oslo_log import log as logging
from tempest.common import utils as tutils
from tempest.lib import decorators
from tempest.lib import exceptions

from neutron.common import utils
from neutron.services.qos import qos_consts
from neutron.tests.tempest.api import base as base_api
from neutron.tests.tempest.common import ssh
from neutron.tests.tempest import config
from neutron.tests.tempest.scenario import base
from neutron.tests.tempest.scenario import constants
from neutron.tests.tempest.scenario import exceptions as sc_exceptions

CONF = config.CONF
LOG = logging.getLogger(__name__)


def _try_connect(host_ip, port):
    try:
        client_socket = socket.socket(socket.AF_INET,
                                      socket.SOCK_STREAM)
        client_socket.connect((host_ip, port))
        return client_socket
    except socket.error as serr:
        if serr.errno == errno.ECONNREFUSED:
            raise sc_exceptions.SocketConnectionRefused(host=host_ip,
                                                        port=port)
        else:
            raise


def _connect_socket(host, port):
    """Try to initiate a connection to a host using an ip address
    and a port.

    Trying couple of times until a timeout is reached in case the listening
    host is not ready yet.
    """

    start = time.time()
    while True:
        try:
            return _try_connect(host, port)
        except sc_exceptions.SocketConnectionRefused:
            if time.time() - start > constants.SOCKET_CONNECT_TIMEOUT:
                raise sc_exceptions.ConnectionTimeoutException(host=host,
                                                               port=port)


class QoSTest(base.BaseTempestTestCase):
    credentials = ['primary', 'admin']
    force_tenant_isolation = False

    BUFFER_SIZE = 1024 * 1024
    TOLERANCE_FACTOR = 1.5
    BS = 512
    COUNT = BUFFER_SIZE / BS
    FILE_SIZE = BS * COUNT
    LIMIT_BYTES_SEC = (constants.LIMIT_KILO_BITS_PER_SECOND * 1024
                       * TOLERANCE_FACTOR / 8.0)
    FILE_PATH = "/tmp/img"

    @classmethod
    @tutils.requires_ext(extension="qos", service="network")
    @base_api.require_qos_rule_type(qos_consts.RULE_TYPE_BANDWIDTH_LIMIT)
    def resource_setup(cls):
        super(QoSTest, cls).resource_setup()

    def _create_file_for_bw_tests(self, ssh_client):
        cmd = ("(dd if=/dev/zero bs=%(bs)d count=%(count)d of=%(file_path)s) "
               % {'bs': QoSTest.BS, 'count': QoSTest.COUNT,
               'file_path': QoSTest.FILE_PATH})
        ssh_client.exec_command(cmd)
        cmd = "stat -c %%s %s" % QoSTest.FILE_PATH
        filesize = ssh_client.exec_command(cmd)
        if int(filesize.strip()) != QoSTest.FILE_SIZE:
            raise sc_exceptions.FileCreationFailedException(
                file=QoSTest.FILE_PATH)

    def _check_bw(self, ssh_client, host, port):
        cmd = "killall -q nc"
        try:
            ssh_client.exec_command(cmd)
        except exceptions.SSHExecCommandFailed:
            pass
        cmd = ("(nc -ll -p %(port)d < %(file_path)s > /dev/null &)" % {
                'port': port, 'file_path': QoSTest.FILE_PATH})
        ssh_client.exec_command(cmd)

        start_time = time.time()
        client_socket = _connect_socket(host, port)
        total_bytes_read = 0

        while total_bytes_read < QoSTest.FILE_SIZE:
            data = client_socket.recv(QoSTest.BUFFER_SIZE)
            total_bytes_read += len(data)

        time_elapsed = time.time() - start_time
        bytes_per_second = total_bytes_read / time_elapsed

        LOG.debug("time_elapsed = %(time_elapsed)d, "
                  "total_bytes_read = %(total_bytes_read)d, "
                  "bytes_per_second = %(bytes_per_second)d",
                  {'time_elapsed': time_elapsed,
                   'total_bytes_read': total_bytes_read,
                   'bytes_per_second': bytes_per_second})

        return bytes_per_second <= QoSTest.LIMIT_BYTES_SEC

    @decorators.idempotent_id('1f7ed39b-428f-410a-bd2b-db9f465680df')
    def test_qos(self):
        """This is a basic test that check that a QoS policy with

           a bandwidth limit rule is applied correctly by sending
           a file from the instance to the test node.
           Then calculating the bandwidth every ~1 sec by the number of bits
           received / elapsed time.
        """

        NC_PORT = 1234

        self.setup_network_and_server()
        self.check_connectivity(self.fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                self.keypair['private_key'])
        rulesets = [{'protocol': 'tcp',
                     'direction': 'ingress',
                     'port_range_min': NC_PORT,
                     'port_range_max': NC_PORT,
                     'remote_ip_prefix': '0.0.0.0/0'}]
        self.create_secgroup_rules(rulesets,
                                   self.security_groups[-1]['id'])

        ssh_client = ssh.Client(self.fip['floating_ip_address'],
                                CONF.validation.image_ssh_user,
                                pkey=self.keypair['private_key'])
        policy = self.os_admin.network_client.create_qos_policy(
                                        name='test-policy',
                                        description='test-qos-policy',
                                        shared=True)
        policy_id = policy['policy']['id']
        self.os_admin.network_client.create_bandwidth_limit_rule(
            policy_id, max_kbps=constants.LIMIT_KILO_BITS_PER_SECOND,
            max_burst_kbps=constants.LIMIT_KILO_BITS_PER_SECOND)
        port = self.client.list_ports(network_id=self.network['id'],
                                      device_id=self.server[
                                      'server']['id'])['ports'][0]
        self.os_admin.network_client.update_port(port['id'],
                                                 qos_policy_id=policy_id)
        self._create_file_for_bw_tests(ssh_client)
        utils.wait_until_true(lambda: self._check_bw(
            ssh_client,
            self.fip['floating_ip_address'],
            port=NC_PORT),
            timeout=120,
            sleep=1)
