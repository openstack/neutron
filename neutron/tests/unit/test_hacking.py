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

from neutron.hacking import checks
from neutron.tests import base


class HackingTestCase(base.BaseTestCase):

    def test_log_translations(self):
        logs = ['audit', 'error', 'info', 'warn', 'warning', 'critical',
                'exception']
        levels = ['_LI', '_LW', '_LE', '_LC']
        debug = "LOG.debug('OK')"
        self.assertEqual(
            0, len(list(checks.validate_log_translations(debug, debug, 'f'))))
        for log in logs:
            bad = 'LOG.%s("Bad")' % log
            self.assertEqual(
                1, len(list(checks.validate_log_translations(bad, bad, 'f'))))
            ok = "LOG.%s(_('OK'))" % log
            self.assertEqual(
                0, len(list(checks.validate_log_translations(ok, ok, 'f'))))
            ok = "LOG.%s('OK')    # noqa" % log
            self.assertEqual(
                0, len(list(checks.validate_log_translations(ok, ok, 'f'))))
            ok = "LOG.%s(variable)" % log
            self.assertEqual(
                0, len(list(checks.validate_log_translations(ok, ok, 'f'))))
            for level in levels:
                ok = "LOG.%s(%s('OK'))" % (log, level)
                self.assertEqual(
                    0, len(list(checks.validate_log_translations(ok,
                                                                 ok, 'f'))))

    def test_use_jsonutils(self):
        def __get_msg(fun):
            msg = ("N321: jsonutils.%(fun)s must be used instead of "
                   "json.%(fun)s" % {'fun': fun})
            return [(0, msg)]

        for method in ('dump', 'dumps', 'load', 'loads'):
            self.assertEqual(
                __get_msg(method),
                list(checks.use_jsonutils("json.%s(" % method,
                                          "./neutron/common/rpc.py")))

            self.assertEqual(0,
                len(list(checks.use_jsonutils("jsonx.%s(" % method,
                                              "./neutron/common/rpc.py"))))

            self.assertEqual(0,
                len(list(checks.use_jsonutils("json.%sx(" % method,
                                              "./neutron/common/rpc.py"))))

            self.assertEqual(0,
                len(list(checks.use_jsonutils(
                    "json.%s" % method,
                    "./neutron/plugins/openvswitch/agent/xenapi/etc/xapi.d/"
                    "plugins/netwrap"))))

    def test_no_author_tags(self):
        self.assertIsInstance(checks.no_author_tags("# author: pele"), tuple)
        self.assertIsInstance(checks.no_author_tags("# @author: pele"), tuple)
        self.assertIsInstance(checks.no_author_tags("# @Author: pele"), tuple)
        self.assertIsInstance(checks.no_author_tags("# Author: pele"), tuple)
        self.assertIsInstance(checks.no_author_tags("# Author pele"), tuple)
        self.assertIsInstance(checks.no_author_tags(".. moduleauthor:: pele"),
                              tuple)
        self.assertEqual(2, checks.no_author_tags("# author: pele")[0])
        self.assertEqual(2, checks.no_author_tags("# Author: pele")[0])
        self.assertEqual(3, checks.no_author_tags(".. moduleauthor:: pele")[0])
