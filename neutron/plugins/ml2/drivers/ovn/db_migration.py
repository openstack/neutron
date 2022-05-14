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
from neutron_lib import exceptions
from oslo_db import exception as db_exc
from oslo_log import log as logging
from sqlalchemy.orm import exc as sqla_exc

from neutron.db.models.plugins.ml2 import geneveallocation
from neutron.db.models.plugins.ml2 import vxlanallocation
from neutron.objects import network as network_obj
from neutron.objects import ports as port_obj
from neutron.objects import trunk as trunk_obj


LOG = logging.getLogger(__name__)

VIF_DETAILS_TO_REMOVE = (
    pb_api.VIF_DETAILS_BRIDGE_NAME,
)


def migrate_neutron_database_to_ovn():
    """Change DB content from OVS to OVN mech driver.

     - Changes vxlan network type to Geneve and updates Geneve allocations.
     - Removes bridge name from port binding vif details to support operations
       on instances with a trunk bridge.
     - Updates the port profile for trunk ports.
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

    # Update ``PortBinding`` objects.
    pb_updated = set([])
    pb_missed = set([])
    while True:
        pb_current = port_obj.PortBinding.get_port_id_and_host(
            ctx, vif_type='ovs', vnic_type='normal', status='ACTIVE')
        diff = set(pb_current).difference(pb_updated)
        if not diff:
            break

        for port_id, host in diff:
            try:
                with db_api.CONTEXT_WRITER.using(ctx):
                    pb = port_obj.PortBinding.get_object(ctx, port_id=port_id,
                                                         host=host)
                    if not pb or not pb.vif_details:
                        continue

                    vif_details = pb.vif_details.copy()
                    for detail in VIF_DETAILS_TO_REMOVE:
                        try:
                            del vif_details[detail]
                        except KeyError:
                            pass
                    if vif_details == pb.vif_details:
                        continue

                    pb.vif_details = vif_details
                    pb.update()
            except (exceptions.ObjectNotFound,
                    sqla_exc.StaleDataError,
                    db_exc.DBDeadlock):
                # The PortBinding register has been already modified.
                pb_missed.add(port_id)

        pb_updated.update(diff)

    if pb_missed:
        LOG.warning('The following ports did not update their port binding '
                    'records: %s', ', '.join(pb_missed))

    # Update ``Trunk`` objects.
    trunk_updated = set([])
    while True:
        trunk_current = trunk_obj.Trunk.get_trunk_ids(ctx)
        diff = set(trunk_current).difference(trunk_updated)
        if not diff:
            break

        for trunk_id in diff:
            with db_api.CONTEXT_WRITER.using(ctx):
                trunk = trunk_obj.Trunk.get_object(ctx, id=trunk_id)
                if not trunk:
                    continue

                for subport in trunk.sub_ports:
                    pbs = port_obj.PortBinding.get_objects(
                        ctx, port_id=subport.port_id)
                    for pb in pbs:
                        profile = {}
                        if pb.profile:
                            profile = pb.profile.copy()
                        profile['parent_name'] = trunk.port_id
                        profile['tag'] = subport.segmentation_id
                        if profile == pb.profile:
                            continue

                        pb.profile = profile
                        pb.update()

        trunk_updated.update(diff)
