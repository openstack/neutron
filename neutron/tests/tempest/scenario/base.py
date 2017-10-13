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
import subprocess

import netaddr
from oslo_log import log
from tempest.common.utils import net_utils
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

from neutron.tests.tempest.api import base as base_api
from neutron.tests.tempest.common import ssh
from neutron.tests.tempest import config
from neutron.tests.tempest.scenario import constants

CONF = config.CONF

LOG = log.getLogger(__name__)


class BaseTempestTestCase(base_api.BaseNetworkTest):
    @classmethod
    def resource_setup(cls):
        super(BaseTempestTestCase, cls).resource_setup()

        cls.keypairs = []

    @classmethod
    def resource_cleanup(cls):
        for keypair in cls.keypairs:
            cls.os_primary.keypairs_client.delete_keypair(
                keypair_name=keypair['name'])

        super(BaseTempestTestCase, cls).resource_cleanup()

    def create_server(self, flavor_ref, image_ref, key_name, networks,
                      name=None, security_groups=None):
        """Create a server using tempest lib
        All the parameters are the ones used in Compute API

        Args:
           flavor_ref(str): The flavor of the server to be provisioned.
           image_ref(str):  The image of the server to be provisioned.
           key_name(str): SSH key to to be used to connect to the
                            provisioned server.
           networks(list): List of dictionaries where each represent
               an interface to be attached to the server. For network
               it should be {'uuid': network_uuid} and for port it should
               be {'port': port_uuid}
           name(str): Name of the server to be provisioned.
           security_groups(list): List of dictionaries where
                the keys is 'name' and the value is the name of
                the security group. If it's not passed the default
                security group will be used.
        """

        name = name or data_utils.rand_name('server-test')
        if not security_groups:
            security_groups = [{'name': 'default'}]

        server = self.os_primary.servers_client.create_server(
            name=name,
            flavorRef=flavor_ref,
            imageRef=image_ref,
            key_name=key_name,
            networks=networks,
            security_groups=security_groups)

        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
            waiters.wait_for_server_termination,
            self.os_primary.servers_client, server['server']['id'])
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.os_primary.servers_client.delete_server,
                        server['server']['id'])
        return server

    @classmethod
    def create_keypair(cls, client=None):
        client = client or cls.os_primary.keypairs_client
        name = data_utils.rand_name('keypair-test')
        body = client.create_keypair(name=name)
        cls.keypairs.append(body['keypair'])
        return body['keypair']

    @classmethod
    def create_secgroup_rules(cls, rule_list, secgroup_id=None):
        client = cls.os_primary.network_client
        if not secgroup_id:
            sgs = client.list_security_groups()['security_groups']
            for sg in sgs:
                if sg['name'] == constants.DEFAULT_SECURITY_GROUP:
                    secgroup_id = sg['id']
                    break

        for rule in rule_list:
            direction = rule.pop('direction')
            client.create_security_group_rule(
                direction=direction,
                security_group_id=secgroup_id,
                **rule)

    @classmethod
    def create_loginable_secgroup_rule(cls, secgroup_id=None):
        """This rule is intended to permit inbound ssh

        Allowing ssh traffic traffic from all sources, so no group_id is
        provided.
        Setting a group_id would only permit traffic from ports
        belonging to the same security group.
        """

        rule_list = [{'protocol': 'tcp',
                      'direction': 'ingress',
                      'port_range_min': 22,
                      'port_range_max': 22,
                      'remote_ip_prefix': '0.0.0.0/0'}]
        cls.create_secgroup_rules(rule_list, secgroup_id=secgroup_id)

    @classmethod
    def create_pingable_secgroup_rule(cls, secgroup_id=None):
        """This rule is intended to permit inbound ping
        """

        rule_list = [{'protocol': 'icmp',
                      'direction': 'ingress',
                      'port_range_min': 8,  # type
                      'port_range_max': 0,  # code
                      'remote_ip_prefix': '0.0.0.0/0'}]
        cls.create_secgroup_rules(rule_list, secgroup_id=secgroup_id)

    @classmethod
    def create_router_by_client(cls, is_admin=False, **kwargs):
        kwargs.update({'router_name': data_utils.rand_name('router'),
                       'admin_state_up': True,
                       'external_network_id': CONF.network.public_network_id})
        if not is_admin:
            router = cls.create_router(**kwargs)
        else:
            router = cls.create_admin_router(**kwargs)
        LOG.debug("Created router %s", router['name'])
        cls.routers.append(router)
        return router

    def create_and_associate_floatingip(self, port_id):
        fip = self.os_primary.network_client.create_floatingip(
            CONF.network.public_network_id,
            port_id=port_id)['floatingip']
        self.floating_ips.append(fip)
        return fip

    def setup_network_and_server(self, router=None, **kwargs):
        """Create network resources and a server.

        Creating a network, subnet, router, keypair, security group
        and a server.
        """
        self.network = self.create_network()
        LOG.debug("Created network %s", self.network['name'])
        self.subnet = self.create_subnet(self.network)
        LOG.debug("Created subnet %s", self.subnet['id'])

        secgroup = self.os_primary.network_client.create_security_group(
            name=data_utils.rand_name('secgroup'))
        LOG.debug("Created security group %s",
                  secgroup['security_group']['name'])
        self.security_groups.append(secgroup['security_group'])
        if not router:
            router = self.create_router_by_client(**kwargs)
        self.create_router_interface(router['id'], self.subnet['id'])
        self.keypair = self.create_keypair()
        self.create_loginable_secgroup_rule(
            secgroup_id=secgroup['security_group']['id'])
        self.server = self.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=self.keypair['name'],
            networks=[{'uuid': self.network['id']}],
            security_groups=[{'name': secgroup['security_group']['name']}])
        waiters.wait_for_server_status(self.os_primary.servers_client,
                                       self.server['server']['id'],
                                       constants.SERVER_STATUS_ACTIVE)
        self.port = self.client.list_ports(network_id=self.network['id'],
                                           device_id=self.server[
                                               'server']['id'])['ports'][0]
        self.fip = self.create_and_associate_floatingip(self.port['id'])

    def check_connectivity(self, host, ssh_user, ssh_key, servers=None):
        ssh_client = ssh.Client(host, ssh_user, pkey=ssh_key)
        try:
            ssh_client.test_connection_auth()
        except lib_exc.SSHTimeout as ssh_e:
            LOG.debug(ssh_e)
            self._log_console_output(servers)
            raise

    def _log_console_output(self, servers=None):
        if not CONF.compute_feature_enabled.console_output:
            LOG.debug('Console output not supported, cannot log')
            return
        if not servers:
            servers = self.os_primary.servers_client.list_servers()
            servers = servers['servers']
        for server in servers:
            try:
                console_output = (
                    self.os_primary.servers_client.get_console_output(
                        server['id'])['output'])
                LOG.debug('Console output for %s\nbody=\n%s',
                          server['id'], console_output)
            except lib_exc.NotFound:
                LOG.debug("Server %s disappeared(deleted) while looking "
                          "for the console log", server['id'])

    def _check_remote_connectivity(self, source, dest, should_succeed=True,
                                   nic=None, mtu=None, fragmentation=True):
        """check ping server via source ssh connection

        :param source: RemoteClient: an ssh connection from which to ping
        :param dest: and IP to ping against
        :param should_succeed: boolean should ping succeed or not
        :param nic: specific network interface to ping from
        :param mtu: mtu size for the packet to be sent
        :param fragmentation: Flag for packet fragmentation
        :returns: boolean -- should_succeed == ping
        :returns: ping is false if ping failed
        """
        def ping_host(source, host, count=CONF.validation.ping_count,
                      size=CONF.validation.ping_size, nic=None, mtu=None,
                      fragmentation=True):
            addr = netaddr.IPAddress(host)
            cmd = 'ping6' if addr.version == 6 else 'ping'
            if nic:
                cmd = 'sudo {cmd} -I {nic}'.format(cmd=cmd, nic=nic)
            if mtu:
                if not fragmentation:
                    cmd += ' -M do'
                size = str(net_utils.get_ping_payload_size(
                    mtu=mtu, ip_version=addr.version))
            cmd += ' -c{0} -w{0} -s{1} {2}'.format(count, size, host)
            return source.exec_command(cmd)

        def ping_remote():
            try:
                result = ping_host(source, dest, nic=nic, mtu=mtu,
                                   fragmentation=fragmentation)

            except lib_exc.SSHExecCommandFailed:
                LOG.warning('Failed to ping IP: %s via a ssh connection '
                            'from: %s.', dest, source.host)
                return not should_succeed
            LOG.debug('ping result: %s', result)
            # Assert that the return traffic was from the correct
            # source address.
            from_source = 'from %s' % dest
            self.assertIn(from_source, result)
            return should_succeed

        return test_utils.call_until_true(ping_remote,
                                          CONF.validation.ping_timeout,
                                          1)

    def check_remote_connectivity(self, source, dest, should_succeed=True,
                                  nic=None, mtu=None, fragmentation=True):
        self.assertTrue(self._check_remote_connectivity(
            source, dest, should_succeed, nic, mtu, fragmentation))

    def ping_ip_address(self, ip_address, should_succeed=True,
                        ping_timeout=None, mtu=None):
        # the code is taken from tempest/scenario/manager.py in tempest git
        timeout = ping_timeout or CONF.validation.ping_timeout
        cmd = ['ping', '-c1', '-w1']

        if mtu:
            cmd += [
                # don't fragment
                '-M', 'do',
                # ping receives just the size of ICMP payload
                '-s', str(net_utils.get_ping_payload_size(mtu, 4))
            ]
        cmd.append(ip_address)

        def ping():
            proc = subprocess.Popen(cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            proc.communicate()

            return (proc.returncode == 0) == should_succeed

        caller = test_utils.find_test_caller()
        LOG.debug('%(caller)s begins to ping %(ip)s in %(timeout)s sec and the'
                  ' expected result is %(should_succeed)s', {
                      'caller': caller, 'ip': ip_address, 'timeout': timeout,
                      'should_succeed':
                      'reachable' if should_succeed else 'unreachable'
                  })
        result = test_utils.call_until_true(ping, timeout, 1)
        LOG.debug('%(caller)s finishes ping %(ip)s in %(timeout)s sec and the '
                  'ping result is %(result)s', {
                      'caller': caller, 'ip': ip_address, 'timeout': timeout,
                      'result': 'expected' if result else 'unexpected'
                  })
        return result
