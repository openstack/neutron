# Copyright (c) 2016 Red Hat, Inc.
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

import mock

from neutron.agent.common import ovs_lib
from neutron.agent.ovsdb import api
from neutron.agent.ovsdb import impl_idl
from neutron.common import utils
from neutron.tests.common import net_helpers
from neutron.tests.functional import base


# NOTE(twilson) functools.partial does not work for this
def trpatch(*args, **kwargs):
    def wrapped(fn):
        return mock.patch.object(impl_idl.NeutronOVSDBTransaction,
                                 *args, **kwargs)(fn)
    return wrapped


class ImplIdlTestCase(base.BaseSudoTestCase):
    def setUp(self):
        super(ImplIdlTestCase, self).setUp()
        self.config(group='OVS', ovsdb_interface='native')
        self.ovs = ovs_lib.BaseOVS()
        self.brname = utils.get_rand_device_name(net_helpers.BR_PREFIX)
        # Make sure exceptions pass through by calling do_post_commit directly
        mock.patch.object(
            impl_idl.NeutronOVSDBTransaction, "post_commit",
            side_effect=impl_idl.NeutronOVSDBTransaction.do_post_commit,
            autospec=True).start()

    def _add_br(self):
        # NOTE(twilson) we will be raising exceptions with add_br, so schedule
        # cleanup before that.
        self.addCleanup(self.ovs.delete_bridge, self.brname)
        ovsdb = self.ovs.ovsdb
        with ovsdb.transaction(check_error=True) as tr:
            tr.add(ovsdb.add_br(self.brname))
        return tr

    def _add_br_and_test(self):
        self._add_br()
        ofport = self.ovs.db_get_val("Interface", self.brname, "ofport")
        self.assertTrue(int(ofport))
        self.assertGreater(ofport, -1)

    def test_post_commit_vswitchd_completed_no_failures(self):
        self._add_br_and_test()

    @trpatch("vswitchd_has_completed", return_value=True)
    @trpatch("post_commit_failed_interfaces", return_value=["failed_if1"])
    @trpatch("timeout_exceeded", return_value=False)
    def test_post_commit_vswitchd_completed_failures(self, *args):
        self.assertRaises(impl_idl.VswitchdInterfaceAddException, self._add_br)

    @trpatch("vswitchd_has_completed", return_value=False)
    def test_post_commit_vswitchd_incomplete_timeout(self, *args):
        # Due to timing issues we may rarely hit the global timeout, which
        # raises RuntimeError to match the vsctl implementation
        self.ovs.vsctl_timeout = 3
        self.assertRaises((api.TimeoutException, RuntimeError), self._add_br)
