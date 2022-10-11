# Copyright 2022 Red Hat, Inc.
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

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.tests.functional import base


class TestCreateNeutronPgDrop(base.TestOVNFunctionalBase):
    def test_already_existing(self):
        # Make sure pre-fork initialize created the table
        existing_pg = self.nb_api.pg_get(
            ovn_const.OVN_DROP_PORT_GROUP_NAME).execute()
        self.assertIsNotNone(existing_pg)

        # make an attempt to create it again
        utils.create_neutron_pg_drop()

        pg = self.nb_api.pg_get(ovn_const.OVN_DROP_PORT_GROUP_NAME).execute()
        self.assertEqual(existing_pg.uuid, pg.uuid)

    def test_non_existing(self):
        # Delete the neutron_pg_drop created by pre-fork initialize
        self.nb_api.pg_del(ovn_const.OVN_DROP_PORT_GROUP_NAME).execute()
        pg = self.nb_api.pg_get(ovn_const.OVN_DROP_PORT_GROUP_NAME).execute()
        self.assertIsNone(pg)

        utils.create_neutron_pg_drop()

        pg = self.nb_api.pg_get(ovn_const.OVN_DROP_PORT_GROUP_NAME).execute()
        self.assertIsNotNone(pg)

        directions = ['to-lport', 'from-lport']
        matches = ['outport == @neutron_pg_drop && ip',
                   'inport == @neutron_pg_drop && ip']

        # Make sure ACLs are correct
        self.assertEqual(2, len(pg.acls))
        acl1, acl2 = pg.acls

        self.assertEqual('drop', acl1.action)
        self.assertIn(acl1.direction, directions)
        directions.remove(acl1.direction)
        self.assertIn(acl1.match, matches)
        matches.remove(acl1.match)

        self.assertEqual(directions[0], acl2.direction)
        self.assertEqual('drop', acl2.action)
        self.assertEqual(matches[0], acl2.match)
