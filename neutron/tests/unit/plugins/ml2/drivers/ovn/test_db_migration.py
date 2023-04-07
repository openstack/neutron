# Copyright 2021 Red Hat, Inc.
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

from unittest import mock

from neutron_lib.api.definitions import portbindings as pb
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import context as n_context
from neutron_lib.db import api as db_api
from neutron_lib import exceptions
from oslo_utils import uuidutils

from neutron.db.models.plugins.ml2 import geneveallocation
from neutron.db.models.plugins.ml2 import vxlanallocation
from neutron.objects import ports as port_obj
from neutron.objects import trunk as trunk_obj
from neutron.plugins.ml2.drivers.ovn import db_migration
from neutron.tests.unit.plugins.ml2.drivers.ovn.mech_driver import (
    test_mech_driver)


class TestMigrateNeutronDatabaseToOvn(
        test_mech_driver.TestOVNMechanismDriverBase):

    def _create_ml2_ovs_test_resources(self, vif_details_list):
        self.subport_profiles = {}
        ctx = n_context.get_admin_context()
        for sid in range(1, 6):
            net_arg = {pnet.NETWORK_TYPE: 'vxlan',
                       pnet.SEGMENTATION_ID: sid}
            network_id = self._make_network(
                self.fmt, 'net%d' % sid, True, as_admin=True,
                arg_list=(pnet.NETWORK_TYPE,
                          pnet.SEGMENTATION_ID,),
                **net_arg
            )['network']['id']

        for vif_details in vif_details_list:
            port = self._make_port(self.fmt, network_id)['port']
            port_o = port_obj.PortBinding.get_object(
                ctx, port_id=port['id'], host='')
            port_o.vif_type = 'ovs'
            port_o.vif_details = vif_details
            port_o.update()

        for i in range(1, 4):
            port = self._make_port(self.fmt, network_id)['port']
            subport1 = self._make_port(self.fmt, network_id)['port']
            subport2 = self._make_port(self.fmt, network_id)['port']

            trunk_id = uuidutils.generate_uuid()

            subports = [trunk_obj.SubPort(
                ctx,
                port_id=subport1['id'],
                trunk_id=trunk_id,
                segmentation_type="vlan",
                segmentation_id=i * 10 + j) for j in range(2)]

            trunk = trunk_obj.Trunk(
                ctx,
                id=trunk_id,
                port_id=port['id'],
                project_id='foo',
                subports=subports)
            trunk.create()

            subport_pb = port_obj.PortBinding.get_object(
                ctx, port_id=subport1['id'], host='')
            self.assertFalse(subport_pb.profile)

            self.subport_profiles[subport1['id']] = {"parent_name": port['id'],
                                                     "tag": i * 10}
            self.subport_profiles[subport2['id']] = {"parent_name": port['id'],
                                                     "tag": i * 10 + 1}

        # set something to the last subport port binding
        subport_pb = port_obj.PortBinding.get_object(
            ctx, port_id=subport2['id'], host='')
        # need to generate new id
        subport_pb.profile = subport_pb.profile.copy()
        subport_pb.profile['foo'] = 'bar'
        subport_pb.update()

        self.subport_profiles[subport2['id']]["foo"] = "bar"

    def _validate_resources_after_migration(self, expected_vif_details):
        ctx = n_context.get_admin_context()

        # Check network types
        networks = self.plugin.get_networks(ctx)
        for network in networks:
            self.assertEqual("geneve", network["provider:network_type"])

        with db_api.CONTEXT_READER.using(ctx) as session:
            # Check there are no vxlan allocations
            vxlan_allocations = session.query(
                vxlanallocation.VxlanAllocation).filter(
                    vxlanallocation.VxlanAllocation.allocated == True # noqa
                        ).all()
            self.assertFalse(vxlan_allocations)

            # Check all the networks have Geneve allocations
            geneve_allocations = session.query(
                geneveallocation.GeneveAllocation).filter(
                    geneveallocation.GeneveAllocation.allocated == True # noqa
                        ).all()
            self.assertEqual(len(networks), len(geneve_allocations))

        # Check port bindings vif details are as expected
        ports = self.plugin.get_ports(ctx)
        for port in ports:
            self.assertIn(port['binding:vif_details'], expected_vif_details)

        # Check port profiles for subport ports
        for trunk in trunk_obj.Trunk.get_objects(ctx):
            for subport in trunk.sub_ports:
                port = self.plugin.get_port(ctx, id=subport.port_id)
                self.assertEqual(
                    self.subport_profiles[subport.port_id],
                    port["binding:profile"])

    def test_db_migration(self):
        """Test the DB migration

        It creates 5 vxlan networks, each should get a vxlan vni allocated.
        Then it creates 3 ports with different vif details.

        After the DB migration the vxlan networks should not be allocated but
        be geneve type and have geneve allocations. Also the port binding vif
        details should not contain hybrid plugging, bridge name for trunk and
        l2 connectivity for OVS agent.
        """
        vif_details_list = [
            {pb.CAP_PORT_FILTER: "true",
             pb.OVS_HYBRID_PLUG: "true",
             pb.VIF_DETAILS_BRIDGE_NAME: "foo",
             pb.VIF_DETAILS_CONNECTIVITY: pb.CONNECTIVITY_L2},
            {pb.CAP_PORT_FILTER: "true",
             pb.VIF_DETAILS_BRIDGE_NAME: "foo"},
            {"foo": "bar"},
            {},
        ]
        expected_vif_details = [
            {pb.CAP_PORT_FILTER: "true",
             pb.OVS_HYBRID_PLUG: "true",
             pb.VIF_DETAILS_CONNECTIVITY: pb.CONNECTIVITY_L2},
            {pb.CAP_PORT_FILTER: "true"},
            {"foo": "bar"},
            {},
        ]

        self._create_ml2_ovs_test_resources(vif_details_list)
        db_migration.migrate_neutron_database_to_ovn()
        self._validate_resources_after_migration(expected_vif_details)

    def test_db_migration_with_pb_not_found(self):
        vif_details_list = [
            {pb.CAP_PORT_FILTER: "true",
             pb.OVS_HYBRID_PLUG: "true",
             pb.VIF_DETAILS_BRIDGE_NAME: "foo",
             pb.VIF_DETAILS_CONNECTIVITY: "l2"},
            {pb.CAP_PORT_FILTER: "true",
             pb.VIF_DETAILS_BRIDGE_NAME: "foo"},
            {"foo": "bar"},
            {},
        ]

        self._create_ml2_ovs_test_resources(vif_details_list)
        with mock.patch.object(
                port_obj.PortBinding, 'update',
                side_effect=exceptions.ObjectNotFound(id='foo')):
            with mock.patch.object(trunk_obj.Trunk, 'get_objects',
                                   return_value=[]):
                db_migration.migrate_neutron_database_to_ovn()
        self._validate_resources_after_migration(vif_details_list)
