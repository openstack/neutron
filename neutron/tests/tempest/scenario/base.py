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

from tempest.common import waiters
from tempest.lib.common import ssh
from tempest.lib.common.utils import data_utils

from neutron.tests.tempest.api import base as base_api
from neutron.tests.tempest import config
from neutron.tests.tempest.scenario import constants

CONF = config.CONF


class BaseTempestTestCase(base_api.BaseNetworkTest):
    @classmethod
    def resource_setup(cls):
        super(BaseTempestTestCase, cls).resource_setup()

        cls.servers = []
        cls.keypairs = []

    @classmethod
    def resource_cleanup(cls):
        for server in cls.servers:
            cls.manager.servers_client.delete_server(server)
            waiters.wait_for_server_termination(cls.manager.servers_client,
                                                server)

        for keypair in cls.keypairs:
            cls.manager.keypairs_client.delete_keypair(
                keypair_name=keypair['name'])

        super(BaseTempestTestCase, cls).resource_cleanup()

    @classmethod
    def create_server(cls, flavor_ref, image_ref, key_name, networks,
                      name=None):
        name = name or data_utils.rand_name('server-test')
        server = cls.manager.servers_client.create_server(
            name=name, flavorRef=flavor_ref,
            imageRef=image_ref,
            key_name=key_name,
            networks=networks)
        cls.servers.append(server['server']['id'])
        return server

    @classmethod
    def create_keypair(cls, client=None):
        client = client or cls.manager.keypairs_client
        name = data_utils.rand_name('keypair-test')
        body = client.create_keypair(name=name)
        cls.keypairs.append(body['keypair'])
        return body['keypair']

    @classmethod
    def create_secgroup_rules(cls, rule_list, secgroup_id=None):
        client = cls.manager.network_client
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
    def create_router_and_interface(cls, subnet_id):
        router = cls.create_router(
            data_utils.rand_name('router'), admin_state_up=True,
            external_network_id=CONF.network.public_network_id)
        cls.create_router_interface(router['id'], subnet_id)
        cls.routers.append(router)
        return router

    @classmethod
    def create_and_associate_floatingip(cls, port_id):
        fip = cls.manager.network_client.create_floatingip(
            CONF.network.public_network_id,
            port_id=port_id)['floatingip']
        cls.floating_ips.append(fip)
        return fip

    @classmethod
    def check_connectivity(cls, host, ssh_user, ssh_key=None):
        ssh_client = ssh.Client(host, ssh_user, pkey=ssh_key)
        ssh_client.test_connection_auth()

    @classmethod
    def setup_network_and_server(cls):
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)

        cls.create_router_and_interface(cls.subnet['id'])
        cls.keypair = cls.create_keypair()
        cls.create_loginable_secgroup_rule()
        cls.server = cls.create_server(
            flavor_ref=CONF.compute.flavor_ref,
            image_ref=CONF.compute.image_ref,
            key_name=cls.keypair['name'],
            networks=[{'uuid': cls.network['id']}])
        waiters.wait_for_server_status(cls.manager.servers_client,
                                       cls.server['server']['id'],
                                       constants.SERVER_STATUS_ACTIVE)
        port = cls.client.list_ports(network_id=cls.network['id'],
                                     device_id=cls.server[
                                          'server']['id'])['ports'][0]
        cls.fip = cls.create_and_associate_floatingip(port['id'])
