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

from neutron_lib.api.definitions import portbindings as pb_api
from neutron_lib import context as n_context
from neutron_lib.db import api as db_api

from neutron.db.models.plugins.ml2 import geneveallocation
from neutron.db.models.plugins.ml2 import vxlanallocation
from neutron.objects import network as network_obj
from neutron.objects import ports as port_obj
from neutron.objects import trunk as trunk_obj

VIF_DETAILS_TO_REMOVE = (
    pb_api.OVS_HYBRID_PLUG,
    pb_api.VIF_DETAILS_BRIDGE_NAME,
    pb_api.VIF_DETAILS_CONNECTIVITY)


def migrate_neutron_database_to_ovn(plugin):
    """Change DB content from OVS to OVN mech driver.

     - Changes vxlan network type to Geneve and updates Geneve allocations.
     - Removes unnecessary settings from port binding vif details, such as
       connectivity, bridge_name and ovs_hybrid_plug, as they are not used by
       OVN.
    """
    ctx = n_context.get_admin_context()
    with db_api.CONTEXT_WRITER.using(ctx) as session:
        # Change network type from vxlan geneve
        segments = network_obj.NetworkSegment.get_objects(
            ctx, network_type='vxlan')
        for segment in segments:
            segment.network_type = 'geneve'
            segment.update()
            # Update Geneve allocation for the segment
            session.query(geneveallocation.GeneveAllocation).filter(
                geneveallocation.GeneveAllocation.geneve_vni ==
                segment.segmentation_id).update({"allocated": True})
            # Zero Vxlan allocations
            session.query(vxlanallocation.VxlanAllocation).filter(
                vxlanallocation.VxlanAllocation.vxlan_vni ==
                segment.segmentation_id).update({"allocated": False})

    port_bindings = port_obj.PortBinding.get_objects(
        ctx, vif_type='ovs', vnic_type='normal', status='ACTIVE')
    for pb in port_bindings:
        if not pb.vif_details:
            continue
        vif_details = pb.vif_details.copy()
        for detail in VIF_DETAILS_TO_REMOVE:
            try:
                del vif_details[detail]
            except KeyError:
                pass
        if vif_details != pb.vif_details:
            pb.vif_details = vif_details
            pb.update()

    for trunk in trunk_obj.Trunk.get_objects(ctx):
        for subport in trunk.sub_ports:
            pbs = port_obj.PortBinding.get_objects(
                ctx, port_id=subport.port_id)
            for pb in pbs:
                profile = {}
                if pb.profile:
                    profile = pb.profile.copy()
                profile['parent_name'] = trunk.port_id
                profile['tag'] = subport.segmentation_id
                if profile != pb.profile:
                    pb.profile = profile
                    pb.update()
