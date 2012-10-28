# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Locaweb.
# All Rights Reserved.
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
#
# @author: Juliano Martinez, Locaweb.

import os
import inspect
import unittest

import mox

from quantum.agent.linux import iptables_manager


class IptablesManagerStateFulTestCase(unittest.TestCase):

    def setUp(self):
        self.mox = mox.Mox()
        self.root_helper = 'sudo'
        self.iptables = (iptables_manager.
                         IptablesManager(root_helper=self.root_helper))
        self.mox.StubOutWithMock(self.iptables, "execute")

    def tearDown(self):
        self.mox.UnsetStubs()

    def test_binary_name(self):
        self.assertEqual(iptables_manager.binary_name,
                         os.path.basename(inspect.stack()[-1][1])[:16])

    def test_add_and_remove_chain(self):
        bn = iptables_manager.binary_name
        self.iptables.execute(['iptables-save', '-t', 'filter'],
                              root_helper=self.root_helper).AndReturn('')

        nat_dump = (':%s-OUTPUT - [0:0]\n:%s-snat - [0:0]\n:%s-PREROUTING -'
                    ' [0:0]\n:%s-float-snat - [0:0]\n:%s-POSTROUTING - [0:0]'
                    '\n:quantum-postrouting-bottom - [0:0]\n-A PREROUTING -j'
                    ' %s-PREROUTING\n-A OUTPUT -j %s-OUTPUT\n-A POSTROUTING '
                    '-j %s-POSTROUTING\n-A POSTROUTING -j quantum-postroutin'
                    'g-bottom\n-A quantum-postrouting-bottom -j %s-snat\n-A '
                    '%s-snat -j %s-float-snat\n' % (bn, bn, bn, bn, bn, bn,
                    bn, bn, bn, bn, bn))

        self.iptables.execute(['iptables-restore'],
                              process_input=(':%s-FORWARD - [0:0]\n:%s-INPUT'
                              ' - [0:0]\n:%s-local - [0:0]\n:%s-filter - [0:'
                              '0]\n:%s-OUTPUT - [0:0]\n:quantum-filter-top -'
                              ' [0:0]\n-A FORWARD -j quantum-filter-top\n-A '
                              'OUTPUT -j quantum-filter-top\n-A quantum-filt'
                              'er-top -j %s-local\n-A INPUT -j %s-INPUT\n-A '
                              'OUTPUT -j %s-OUTPUT\n-A FORWARD -j %s-FORWARD'
                              '\n' % (bn, bn, bn, bn, bn, bn, bn, bn, bn)
                              ), root_helper=self.root_helper).AndReturn(None)

        self.iptables.execute(['iptables-save', '-t', 'nat'],
                              root_helper=self.root_helper).AndReturn('')

        self.iptables.execute(['iptables-restore'],
                              process_input=nat_dump,
                              root_helper=self.root_helper).AndReturn(None)

        self.iptables.execute(['iptables-save', '-t', 'filter'],
                              root_helper=self.root_helper).AndReturn('')

        self.iptables.execute(['iptables-restore'],
                              process_input=(':%s-FORWARD - [0:0]\n:%s-INPUT'
                              ' - [0:0]\n:%s-local - [0:0]\n:%s-OUTPUT - [0:'
                              '0]\n:quantum-filter-top - [0:0]\n-A FORWARD -'
                              'j quantum-filter-top\n-A OUTPUT -j quantum-fi'
                              'lter-top\n-A quantum-filter-top -j %s-local\n'
                              '-A INPUT -j %s-INPUT\n-A OUTPUT -j %s-OUTPUT'
                              '\n-A FORWARD -j %s-FORWARD\n' % (bn, bn, bn, bn,
                              bn, bn, bn, bn)), root_helper=self.root_helper
                              ).AndReturn(None)

        self.iptables.execute(['iptables-save', '-t', 'nat'],
                              root_helper=self.root_helper).AndReturn('')

        self.iptables.execute(['iptables-restore'],
                              process_input=nat_dump,
                              root_helper=self.root_helper).AndReturn(None)

        self.mox.ReplayAll()

        self.iptables.ipv4['filter'].add_chain('filter')
        self.iptables.apply()

        self.iptables.ipv4['filter'].remove_chain('filter')
        self.iptables.apply()

        self.mox.VerifyAll()

    def test_add_filter_rule(self):
        bn = iptables_manager.binary_name
        self.iptables.execute(['iptables-save', '-t', 'filter'],
                              root_helper=self.root_helper).AndReturn('')

        nat_dump = (':%s-OUTPUT - [0:0]\n:%s-snat - [0:0]\n:%s-PREROUTING -'
                    ' [0:0]\n:%s-float-snat - [0:0]\n:%s-POSTROUTING - [0:0]'
                    '\n:quantum-postrouting-bottom - [0:0]\n-A PREROUTING -j'
                    ' %s-PREROUTING\n-A OUTPUT -j %s-OUTPUT\n-A POSTROUTING '
                    '-j %s-POSTROUTING\n-A POSTROUTING -j quantum-postroutin'
                    'g-bottom\n-A quantum-postrouting-bottom -j %s-snat\n-A '
                    '%s-snat -j %s-float-snat\n' % (bn, bn, bn, bn, bn, bn,
                    bn, bn, bn, bn, bn))

        self.iptables.execute(['iptables-restore'],
                              process_input=(':%s-FORWARD - [0:0]\n:%s-INPUT'
                              ' - [0:0]\n:%s-local - [0:0]\n:%s-filter - [0:'
                              '0]\n:%s-OUTPUT - [0:0]\n:quantum-filter-top -'
                              ' [0:0]\n-A FORWARD -j quantum-filter-top\n-A '
                              'OUTPUT -j quantum-filter-top\n-A quantum-filt'
                              'er-top -j %s-local\n-A INPUT -j %s-INPUT\n-A '
                              'OUTPUT -j %s-OUTPUT\n-A FORWARD -j %s-FORWARD'
                              '\n-A %s-filter -j DROP\n-A %s-INPUT -s 0/0 -d'
                              ' 192.168.0.2 -j %s-filter\n' % (bn, bn, bn, bn,
                              bn, bn, bn, bn, bn, bn, bn, bn)),
                              root_helper=self.root_helper).AndReturn(None)

        self.iptables.execute(['iptables-save', '-t', 'nat'],
                              root_helper=self.root_helper).AndReturn('')

        self.iptables.execute(['iptables-restore'],
                              process_input=nat_dump,
                              root_helper=self.root_helper).AndReturn(None)

        self.iptables.execute(['iptables-save', '-t', 'filter'],
                              root_helper=self.root_helper).AndReturn('')

        self.iptables.execute(['iptables-restore'],
                              process_input=(':%s-FORWARD - [0:0]\n:%s-INPUT -'
                              ' [0:0]\n:%s-local - [0:0]\n:%s-OUTPUT - [0:0]\n'
                              ':quantum-filter-top - [0:0]\n-A FORWARD -j quan'
                              'tum-filter-top\n-A OUTPUT -j quantum-filter-top'
                              '\n-A quantum-filter-top -j %s-local\n-A INPUT -'
                              'j %s-INPUT\n-A OUTPUT -j %s-OUTPUT\n-A FORWARD '
                              '-j %s-FORWARD\n' % (bn, bn, bn, bn, bn, bn, bn,
                              bn)), root_helper=self.root_helper
                              ).AndReturn(None)

        self.iptables.execute(['iptables-save', '-t', 'nat'],
                              root_helper=self.root_helper).AndReturn('')

        self.iptables.execute(['iptables-restore'],
                              process_input=nat_dump,
                              root_helper=self.root_helper).AndReturn(None)

        self.mox.ReplayAll()

        self.iptables.ipv4['filter'].add_chain('filter')
        self.iptables.ipv4['filter'].add_rule('filter', '-j DROP')
        self.iptables.ipv4['filter'].add_rule('INPUT',
                                              '-s 0/0 -d 192.168.0.2 -j'
                                              ' %s-filter' %
                                              (iptables_manager.binary_name))
        self.iptables.apply()

        self.iptables.ipv4['filter'].remove_rule('filter', '-j DROP')
        self.iptables.ipv4['filter'].remove_rule('INPUT',
                                                 '-s 0/0 -d 192.168.0.2 -j'
                                                 ' %s-filter' %
                                                 (iptables_manager.
                                                  binary_name))
        self.iptables.ipv4['filter'].remove_chain('filter')

        self.iptables.apply()
        self.mox.VerifyAll()

    def test_add_nat_rule(self):
        bn = iptables_manager.binary_name

        filter_dump = (':%s-FORWARD - [0:0]\n:%s-INPUT - [0:0]\n:%s-local - '
                       '[0:0]\n:%s-OUTPUT - [0:0]\n:quantum-filter-top - [0:'
                       '0]\n-A FORWARD -j quantum-filter-top\n-A OUTPUT -j q'
                       'uantum-filter-top\n-A quantum-filter-top -j %s-local'
                       '\n-A INPUT -j %s-INPUT\n-A OUTPUT -j %s-OUTPUT\n-A F'
                       'ORWARD -j %s-FORWARD\n' % (bn, bn, bn, bn, bn,
                       bn, bn, bn))

        self.iptables.execute(['iptables-save', '-t', 'filter'],
                              root_helper=self.root_helper).AndReturn('')

        self.iptables.execute(['iptables-restore'],
                              process_input=filter_dump,
                              root_helper=self.root_helper).AndReturn(None)

        self.iptables.execute(['iptables-save', '-t', 'nat'],
                              root_helper=self.root_helper).AndReturn('')

        self.iptables.execute(['iptables-restore'],
                              process_input=(':%s-float-snat - [0:0]\n:%s-POS'
                              'TROUTING - [0:0]\n:%s-PREROUTING - [0:0]\n:%s-'
                              'nat - [0:0]\n:%s-OUTPUT - [0:0]\n:%s-snat - [0'
                              ':0]\n:quantum-postrouting-bottom - [0:0]\n-A P'
                              'REROUTING -j %s-PREROUTING\n-A OUTPUT -j %s-OU'
                              'TPUT\n-A POSTROUTING -j %s-POSTROUTING\n-A POS'
                              'TROUTING -j quantum-postrouting-bottom\n-A qua'
                              'ntum-postrouting-bottom -j %s-snat\n-A %s-snat'
                              ' -j %s-float-snat\n-A %s-PREROUTING -d 192.168'
                              '.0.3 -j %s-nat\n-A %s-nat -p tcp --dport 8080 '
                              '-j REDIRECT --to-port 80\n' % (bn, bn, bn, bn,
                              bn, bn, bn, bn, bn, bn, bn, bn, bn, bn, bn)),
                              root_helper=self.root_helper).AndReturn(None)

        self.iptables.execute(['iptables-save', '-t', 'filter'],
                              root_helper=self.root_helper).AndReturn('')

        self.iptables.execute(['iptables-restore'],
                              process_input=filter_dump,
                              root_helper=self.root_helper).AndReturn(None)

        self.iptables.execute(['iptables-save', '-t', 'nat'],
                              root_helper=self.root_helper).AndReturn('')

        self.iptables.execute(['iptables-restore'],
                              process_input=(':%s-float-snat - [0:0]\n:%s-POST'
                              'ROUTING - [0:0]\n:%s-PREROUTING - [0:0]\n:%s-OU'
                              'TPUT - [0:0]\n:%s-snat - [0:0]\n:quantum-postro'
                              'uting-bottom - [0:0]\n-A PREROUTING -j %s-PRERO'
                              'UTING\n-A OUTPUT -j %s-OUTPUT\n-A POSTROUTING -'
                              'j %s-POSTROUTING\n-A POSTROUTING -j quantum-pos'
                              'trouting-bottom\n-A quantum-postrouting-bottom '
                              '-j %s-snat\n-A %s-snat -j %s-float-snat\n' % (
                              bn, bn, bn, bn, bn, bn, bn, bn, bn, bn, bn)
                              ), root_helper=self.root_helper).AndReturn(None)

        self.mox.ReplayAll()
        self.iptables.ipv4['nat'].add_chain('nat')
        self.iptables.ipv4['nat'].add_rule('PREROUTING',
                                           '-d 192.168.0.3 -j %s-nat' %
                                           (iptables_manager.binary_name))
        self.iptables.ipv4['nat'].add_rule('nat',
                                           '-p tcp --dport 8080' +
                                           ' -j REDIRECT --to-port 80')

        self.iptables.apply()

        self.iptables.ipv4['nat'].remove_rule('nat',
                                              '-p tcp --dport 8080 -j'
                                              ' REDIRECT --to-port 80')
        self.iptables.ipv4['nat'].remove_rule('PREROUTING',
                                              '-d 192.168.0.3 -j %s-nat' %
                                              (iptables_manager.binary_name))
        self.iptables.ipv4['nat'].remove_chain('nat')

        self.iptables.apply()
        self.mox.VerifyAll()

    def test_add_rule_to_a_nonexistent_chain(self):
        self.assertRaises(LookupError, self.iptables.ipv4['filter'].add_rule,
                          'nonexistent', '-j DROP')

    def test_remove_nonexistent_chain(self):
        self.mox.StubOutWithMock(iptables_manager, "LOG")
        iptables_manager.LOG.warn(('Attempted to remove chain %s which does '
                                   'not exist'), 'nonexistent')
        self.mox.ReplayAll()
        self.iptables.ipv4['filter'].remove_chain('nonexistent')
        self.mox.VerifyAll()

    def test_remove_nonexistent_rule(self):
        self.mox.StubOutWithMock(iptables_manager, "LOG")
        iptables_manager.LOG.warn('Tried to remove rule that was not there: '
                                  '%(chain)r %(rule)r %(wrap)r %(top)r',
                                  {'wrap': True, 'top': False,
                                   'rule': '-j DROP',
                                   'chain': 'nonexistent'})
        self.mox.ReplayAll()
        self.iptables.ipv4['filter'].remove_rule('nonexistent', '-j DROP')
        self.mox.VerifyAll()


class IptablesManagerStateLessTestCase(unittest.TestCase):

    def setUp(self):
        self.iptables = (iptables_manager.IptablesManager(state_less=True))

    def test_nat_not_found(self):
        self.assertFalse('nat' in self.iptables.ipv4)
