# Copyright 2015 Red Hat, Inc.
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

from concurrent import futures
import itertools
import os
import random
import time

import netaddr
from neutron_lib.tests import tools
from oslo_config import cfg
from oslo_log import log as logging

from neutron.agent.linux import ip_lib
from neutron.common import utils as common_utils
from neutron.conf.agent import common as config
from neutron.tests import base as tests_base
from neutron.tests.common import helpers
from neutron.tests.common import machine_fixtures
from neutron.tests.common import net_helpers
from neutron.tests.fullstack.resources import client as client_resource
from neutron.tests.fullstack.resources import machine
from neutron.tests.unit import testlib_api


# This is the directory from which infra fetches log files for fullstack tests
DEFAULT_LOG_DIR = os.path.join(helpers.get_test_log_path(),
                               'dsvm-fullstack-logs')
ROOTDIR = os.path.dirname(__file__)

LOG = logging.getLogger(__name__)


class BaseFullStackTestCase(testlib_api.MySQLTestCaseMixin,
                            testlib_api.SqlTestCase):
    """Base test class for full-stack tests."""

    BUILD_WITH_MIGRATIONS = True

    # NOTE(slaweq): In fullstack tests there need to be new database created
    # for every test, and one db shouldn't be really shared between tests
    # running by the same worker
    CLEAN_DB_AFTER_TEST = True

    def setUp(self, environment):
        super().setUp()

        tests_base.setup_test_logging(
            cfg.CONF, DEFAULT_LOG_DIR, '%s.txt' % self.get_name())

        # NOTE(zzzeek): the opportunistic DB fixtures have built for
        # us a per-test (or per-process) database.  Set the URL of this
        # database in CONF as the full stack tests need to actually run a
        # neutron server against this database.
        _orig_db_url = cfg.CONF.database.connection
        cfg.CONF.set_override(
            'connection',
            self.engine.url.render_as_string(hide_password=False),
            group='database')
        self.addCleanup(
            cfg.CONF.set_override,
            "connection", _orig_db_url, group="database"
        )

        # NOTE(ihrachys): seed should be reset before environment fixture below
        # since the latter starts services that may rely on generated port
        # numbers
        tools.reset_random_seed()

        # configure test runner to use rootwrap
        self.setup_rootwrap()
        config.setup_privsep()

        self.environment = environment
        self.environment.test_name = self.get_name()
        self.useFixture(self.environment)
        self.client = self.environment.neutron_server.client
        self.safe_client = self.useFixture(
            client_resource.ClientFixture(self.client))

    def get_name(self):
        class_name, test_name = self.id().split(".")[-2:]
        return f"{class_name}.{test_name}"

    def _wait_until_agent_up(self, agent_id):
        def _agent_up():
            agent = self.client.show_agent(agent_id)['agent']
            return agent.get('alive')

        common_utils.wait_until_true(_agent_up)

    def _wait_until_agent_down(self, agent_id):
        def _agent_down():
            agent = self.client.show_agent(agent_id)['agent']
            if not agent.get('alive'):
                # NOTE(slaweq): to avoid race between heartbeat written in the
                # database and response to this API call, lets make sure that
                # agent is really dead. See bug
                # https://bugs.launchpad.net/neutron/+bug/2045757
                # for details.
                # 2 seconds delay should be more than enough to make sure that
                # all pending heartbeats are already written in the Neutron
                # database
                time.sleep(2)
                agent = self.client.show_agent(agent_id)['agent']
            return not agent.get('alive')

        common_utils.wait_until_true(_agent_down)

    def _assert_ping_during_agents_restart(
            self, agents, src_namespace, ips, restart_timeout=30,
            ping_timeout=1, count=10):
        with net_helpers.async_ping(
                src_namespace, ips, timeout=ping_timeout,
                count=count) as done:
            LOG.debug("Restarting agents")
            executor = futures.ThreadPoolExecutor(max_workers=len(agents))
            restarts = [agent.restart(executor=executor)
                        for agent in agents]

            futures.wait(restarts, timeout=restart_timeout)

            self.assertTrue(all(r.done() for r in restarts))
            LOG.debug("Restarting agents - done")

            # It is necessary to give agents time to initialize
            # because some crucial steps (e.g. setting up bridge flows)
            # happen only after RPC is established
            agent_names = ', '.join({agent.process_fixture.process_name
                                     for agent in agents})
            common_utils.wait_until_true(
                done,
                timeout=count * (ping_timeout + 1),
                exception=RuntimeError("Could not ping the other VM, "
                                       "re-starting %s leads to network "
                                       "disruption" % agent_names))

    def _find_available_ips(self, network, subnet, num):
        ports = self.safe_client.list_ports(network_id=network['id'])
        used_ips = netaddr.IPSet(
            [netaddr.IPAddress(ip['ip_address'])
             for port in ports for ip in port['fixed_ips']])
        used_ips.add(netaddr.IPAddress(subnet['gateway_ip']))
        # Note(lajoskatona): Suppose that we have 1 allocation pool for the
        # subnet, that should be quite good assumption for testing.
        valid_ip_pool = subnet['allocation_pools'][0]
        valid_ips = netaddr.IPSet(netaddr.IPRange(
            valid_ip_pool['start'],
            valid_ip_pool['end'])
        )
        valid_ips = valid_ips.difference(used_ips)
        if valid_ips.size < num:
            self.fail("Cannot find enough free IP addresses.")
        initial = random.randint(0, min(valid_ips.size - num, 1000))
        available_ips = itertools.islice(valid_ips, initial, initial + num)
        return [str(available_ip) for available_ip in available_ips]

    def _create_external_vm(self, network, subnet, ip=None):
        ip = ip or subnet['gateway_ip']
        vm = self.useFixture(
            machine_fixtures.FakeMachine(
                self.environment.central_bridge,
                common_utils.ip_to_cidr(ip, 24)))
        # NOTE(slaweq): as ext_net is 'vlan' network type external_vm needs to
        # send packets with proper vlan also
        vm.bridge.set_db_attribute(
            "Port", vm.port.name,
            "tag", network.get("provider:segmentation_id"))
        return vm

    def _prepare_vms_in_net(self, tenant_uuid, network, use_dhcp=False):
        vms = machine.FakeFullstackMachinesList(
            self.useFixture(
                machine.FakeFullstackMachine(
                    host,
                    network['id'],
                    tenant_uuid,
                    self.safe_client,
                    use_dhcp=use_dhcp))
            for host in self.environment.hosts)

        vms.block_until_all_boot()
        if use_dhcp:
            vms.block_until_all_dhcp_config_done()
        return vms

    def assert_namespace_exists(self, ns_name):
        common_utils.wait_until_true(
            lambda: ip_lib.network_namespace_exists(ns_name,
                                                    try_is_ready=True))
