#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import mock

from neutron.agent.linux import ipset_manager
from neutron.tests import base

TEST_SET_ID = 'fake_sgid'
ETHERTYPE = 'IPv4'
TEST_SET_NAME = ipset_manager.IpsetManager.get_name(TEST_SET_ID, ETHERTYPE)
TEST_SET_NAME_NEW = TEST_SET_NAME + ipset_manager.SWAP_SUFFIX
FAKE_IPS = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4',
            '10.0.0.5', '10.0.0.6']


class BaseIpsetManagerTest(base.BaseTestCase):
    def setUp(self):
        super(BaseIpsetManagerTest, self).setUp()
        self.ipset = ipset_manager.IpsetManager()
        self.execute = mock.patch.object(self.ipset, "execute").start()
        self.expected_calls = []
        self.expect_create()
        self.force_sorted_get_set_ips()

    def force_sorted_get_set_ips(self):
        """Force sorted responses by self.ipset._get_new/deleted_set_ips.

        _get_new/deleted_set_ips use internally sets and return randomly
        ordered responses. This method ensures sorted responses from them
        in order to guarantee call order in self.ipset.set_members.
        """
        original_get_new_set_ips = self.ipset._get_new_set_ips
        original_get_deleted_set_ips = self.ipset._get_deleted_set_ips

        def sorted_get_new_set_ips(set_name, expected_ips):
            unsorted = original_get_new_set_ips(set_name, expected_ips)
            return sorted(unsorted)

        def sorted_get_deleted_set_ips(set_name, expected_ips):
            unsorted = original_get_deleted_set_ips(set_name, expected_ips)
            return sorted(unsorted)

        mock.patch.object(self.ipset, '_get_new_set_ips',
                          side_effect=sorted_get_new_set_ips).start()
        mock.patch.object(self.ipset, '_get_deleted_set_ips',
                          side_effect=sorted_get_deleted_set_ips).start()

    def verify_mock_calls(self):
        self.execute.assert_has_calls(self.expected_calls, any_order=False)

    def expect_set(self, addresses):
        temp_input = ['create %s hash:net family inet' % TEST_SET_NAME_NEW]
        temp_input.extend('add %s %s' % (TEST_SET_NAME_NEW, ip)
                          for ip in self.ipset._sanitize_addresses(addresses))
        input = '\n'.join(temp_input)
        self.expected_calls.extend([
            mock.call(['ipset', 'restore', '-exist'],
                      process_input=input,
                      run_as_root=True,
                      check_exit_code=True),
            mock.call(['ipset', 'swap', TEST_SET_NAME_NEW, TEST_SET_NAME],
                      process_input=None,
                      run_as_root=True,
                      check_exit_code=True),
            mock.call(['ipset', 'destroy', TEST_SET_NAME_NEW],
                      process_input=None,
                      run_as_root=True,
                      check_exit_code=False)])

    def expect_add(self, addresses):
        self.expected_calls.extend(
            mock.call(['ipset', 'add', '-exist', TEST_SET_NAME, ip],
                      process_input=None,
                      run_as_root=True,
                      check_exit_code=True)
            for ip in self.ipset._sanitize_addresses(addresses))

    def expect_del(self, addresses):

        self.expected_calls.extend(
            mock.call(['ipset', 'del', TEST_SET_NAME, ip],
                      process_input=None,
                      run_as_root=True,
                      check_exit_code=False)
            for ip in self.ipset._sanitize_addresses(addresses))

    def expect_create(self):
        self.expected_calls.append(
            mock.call(['ipset', 'create', '-exist', TEST_SET_NAME,
                       'hash:net', 'family', 'inet'],
                      process_input=None,
                      run_as_root=True,
                      check_exit_code=True))

    def expect_destroy(self):
        self.expected_calls.append(
            mock.call(['ipset', 'destroy', TEST_SET_NAME],
                      process_input=None,
                      run_as_root=True,
                      check_exit_code=False))

    def add_first_ip(self):
        self.expect_set([FAKE_IPS[0]])
        self.ipset.set_members(TEST_SET_ID, ETHERTYPE, [FAKE_IPS[0]])

    def add_all_ips(self):
        self.expect_set(FAKE_IPS)
        self.ipset.set_members(TEST_SET_ID, ETHERTYPE, FAKE_IPS)


class IpsetManagerTestCase(BaseIpsetManagerTest):

    def test_set_name_exists(self):
        self.add_first_ip()
        self.assertTrue(self.ipset.set_name_exists('N' + ETHERTYPE +
                                                   TEST_SET_ID))

    def test_set_members_with_first_add_member(self):
        self.add_first_ip()
        self.verify_mock_calls()

    def test_set_members_adding_less_than_5(self):
        self.add_first_ip()
        self.expect_add(FAKE_IPS[1:5])
        self.ipset.set_members(TEST_SET_ID, ETHERTYPE, FAKE_IPS[0:5])
        self.verify_mock_calls()

    def test_set_members_deleting_less_than_5(self):
        self.add_all_ips()
        self.expect_del(FAKE_IPS[3:])
        self.ipset.set_members(TEST_SET_ID, ETHERTYPE, FAKE_IPS[0:3])
        self.verify_mock_calls()

    def test_set_members_adding_more_than_5(self):
        self.add_first_ip()
        self.expect_set(FAKE_IPS)
        self.ipset.set_members(TEST_SET_ID, ETHERTYPE, FAKE_IPS)
        self.verify_mock_calls()

    def test_set_members_adding_all_zero_ipv4(self):
        self.expect_set(['0.0.0.0/0'])
        self.ipset.set_members(TEST_SET_ID, ETHERTYPE, ['0.0.0.0/0'])
        self.verify_mock_calls()

    def test_set_members_adding_all_zero_ipv6(self):
        self.expect_set(['::/0'])
        self.ipset.set_members(TEST_SET_ID, ETHERTYPE, ['::/0'])
        self.verify_mock_calls()

    def test_destroy(self):
        self.add_first_ip()
        self.expect_destroy()
        self.ipset.destroy(TEST_SET_ID, ETHERTYPE)
        self.verify_mock_calls()
