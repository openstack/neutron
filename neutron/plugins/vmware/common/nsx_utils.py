# Copyright 2013 VMware Inc.
# All Rights Reserved
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

from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as n_exc
from neutron.extensions import multiprovidernet as mpnet
from neutron.extensions import providernet as pnet
from neutron.openstack.common import log
from neutron.plugins.vmware.api_client import client
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.common import utils as vmw_utils
from neutron.plugins.vmware.dbexts import db as nsx_db
from neutron.plugins.vmware.dbexts import networkgw_db
from neutron.plugins.vmware import nsx_cluster
from neutron.plugins.vmware.nsxlib import l2gateway as l2gwlib
from neutron.plugins.vmware.nsxlib import router as routerlib
from neutron.plugins.vmware.nsxlib import secgroup as secgrouplib
from neutron.plugins.vmware.nsxlib import switch as switchlib

LOG = log.getLogger(__name__)


def fetch_nsx_switches(session, cluster, neutron_net_id):
    """Retrieve logical switches for a neutron network.

    This function is optimized for fetching all the lswitches always
    with a single NSX query.
    If there is more than 1 logical switch (chained switches use case)
    NSX lswitches are queried by 'quantum_net_id' tag. Otherwise the NSX
    lswitch is directly retrieved by id (more efficient).
    """
    nsx_switch_ids = get_nsx_switch_ids(session, cluster, neutron_net_id)
    if len(nsx_switch_ids) > 1:
        lswitches = switchlib.get_lswitches(cluster, neutron_net_id)
    else:
        lswitches = [switchlib.get_lswitch_by_id(
            cluster, nsx_switch_ids[0])]
    return lswitches


def get_nsx_switch_ids(session, cluster, neutron_network_id):
    """Return the NSX switch id for a given neutron network.

    First lookup for mappings in Neutron database. If no mapping is
    found, query the NSX backend and add the mappings.
    """
    nsx_switch_ids = nsx_db.get_nsx_switch_ids(
        session, neutron_network_id)
    if not nsx_switch_ids:
        # Find logical switches from backend.
        # This is a rather expensive query, but it won't be executed
        # more than once for each network in Neutron's lifetime
        nsx_switches = switchlib.get_lswitches(cluster, neutron_network_id)
        if not nsx_switches:
            LOG.warn(_("Unable to find NSX switches for Neutron network %s"),
                     neutron_network_id)
            return
        nsx_switch_ids = []
        with session.begin(subtransactions=True):
            for nsx_switch in nsx_switches:
                nsx_switch_id = nsx_switch['uuid']
                nsx_switch_ids.append(nsx_switch_id)
                # Create DB mapping
                nsx_db.add_neutron_nsx_network_mapping(
                    session,
                    neutron_network_id,
                    nsx_switch_id)
    return nsx_switch_ids


def get_nsx_switch_and_port_id(session, cluster, neutron_port_id):
    """Return the NSX switch and port uuids for a given neutron port.

    First, look up the Neutron database. If not found, execute
    a query on NSX platform as the mapping might be missing because
    the port was created before upgrading to grizzly.

    This routine also retrieves the identifier of the logical switch in
    the backend where the port is plugged. Prior to Icehouse this
    information was not available in the Neutron Database. For dealing
    with pre-existing records, this routine will query the backend
    for retrieving the correct switch identifier.

    As of Icehouse release it is not indeed anymore possible to assume
    the backend logical switch identifier is equal to the neutron
    network identifier.
    """
    nsx_switch_id, nsx_port_id = nsx_db.get_nsx_switch_and_port_id(
        session, neutron_port_id)
    if not nsx_switch_id:
        # Find logical switch for port from backend
        # This is a rather expensive query, but it won't be executed
        # more than once for each port in Neutron's lifetime
        nsx_ports = switchlib.query_lswitch_lports(
            cluster, '*', relations='LogicalSwitchConfig',
            filters={'tag': neutron_port_id,
                     'tag_scope': 'q_port_id'})
        # Only one result expected
        # NOTE(salv-orlando): Not handling the case where more than one
        # port is found with the same neutron port tag
        if not nsx_ports:
            LOG.warn(_("Unable to find NSX port for Neutron port %s"),
                     neutron_port_id)
            # This method is supposed to return a tuple
            return None, None
        nsx_port = nsx_ports[0]
        nsx_switch_id = (nsx_port['_relations']
                         ['LogicalSwitchConfig']['uuid'])
        if nsx_port_id:
            # Mapping already exists. Delete before recreating
            nsx_db.delete_neutron_nsx_port_mapping(
                session, neutron_port_id)
        else:
            nsx_port_id = nsx_port['uuid']
        # (re)Create DB mapping
        nsx_db.add_neutron_nsx_port_mapping(
            session, neutron_port_id,
            nsx_switch_id, nsx_port_id)
    return nsx_switch_id, nsx_port_id


def get_nsx_security_group_id(session, cluster, neutron_id):
    """Return the NSX sec profile uuid for a given neutron sec group.

    First, look up the Neutron database. If not found, execute
    a query on NSX platform as the mapping might be missing.
    NOTE: Security groups are called 'security profiles' on the NSX backend.
    """
    nsx_id = nsx_db.get_nsx_security_group_id(session, neutron_id)
    if not nsx_id:
        # Find security profile on backend.
        # This is a rather expensive query, but it won't be executed
        # more than once for each security group in Neutron's lifetime
        nsx_sec_profiles = secgrouplib.query_security_profiles(
            cluster, '*',
            filters={'tag': neutron_id,
                     'tag_scope': 'q_sec_group_id'})
        # Only one result expected
        # NOTE(salv-orlando): Not handling the case where more than one
        # security profile is found with the same neutron port tag
        if not nsx_sec_profiles:
            LOG.warn(_("Unable to find NSX security profile for Neutron "
                       "security group %s"), neutron_id)
            return
        elif len(nsx_sec_profiles) > 1:
            LOG.warn(_("Multiple NSX security profiles found for Neutron "
                       "security group %s"), neutron_id)
        nsx_sec_profile = nsx_sec_profiles[0]
        nsx_id = nsx_sec_profile['uuid']
        with session.begin(subtransactions=True):
            # Create DB mapping
            nsx_db.add_neutron_nsx_security_group_mapping(
                session, neutron_id, nsx_id)
    return nsx_id


def get_nsx_router_id(session, cluster, neutron_router_id):
    """Return the NSX router uuid for a given neutron router.

    First, look up the Neutron database. If not found, execute
    a query on NSX platform as the mapping might be missing.
    """
    nsx_router_id = nsx_db.get_nsx_router_id(
        session, neutron_router_id)
    if not nsx_router_id:
        # Find logical router from backend.
        # This is a rather expensive query, but it won't be executed
        # more than once for each router in Neutron's lifetime
        nsx_routers = routerlib.query_lrouters(
            cluster, '*',
            filters={'tag': neutron_router_id,
                     'tag_scope': 'q_router_id'})
        # Only one result expected
        # NOTE(salv-orlando): Not handling the case where more than one
        # port is found with the same neutron port tag
        if not nsx_routers:
            LOG.warn(_("Unable to find NSX router for Neutron router %s"),
                     neutron_router_id)
            return
        nsx_router = nsx_routers[0]
        nsx_router_id = nsx_router['uuid']
        with session.begin(subtransactions=True):
            # Create DB mapping
            nsx_db.add_neutron_nsx_router_mapping(
                session,
                neutron_router_id,
                nsx_router_id)
    return nsx_router_id


def create_nsx_cluster(cluster_opts, concurrent_connections, gen_timeout):
    cluster = nsx_cluster.NSXCluster(**cluster_opts)

    def _ctrl_split(x, y):
        return (x, int(y), True)

    api_providers = [_ctrl_split(*ctrl.split(':'))
                     for ctrl in cluster.nsx_controllers]
    cluster.api_client = client.NsxApiClient(
        api_providers, cluster.nsx_user, cluster.nsx_password,
        http_timeout=cluster.http_timeout,
        retries=cluster.retries,
        redirects=cluster.redirects,
        concurrent_connections=concurrent_connections,
        gen_timeout=gen_timeout)
    return cluster


def get_nsx_device_status(cluster, nsx_uuid):
    try:
        status_up = l2gwlib.get_gateway_device_status(
            cluster, nsx_uuid)
        if status_up:
            return networkgw_db.STATUS_ACTIVE
        else:
            return networkgw_db.STATUS_DOWN
    except api_exc.NsxApiException:
        return networkgw_db.STATUS_UNKNOWN
    except n_exc.NotFound:
        return networkgw_db.ERROR


def get_nsx_device_statuses(cluster, tenant_id):
    try:
        status_dict = l2gwlib.get_gateway_devices_status(
            cluster, tenant_id)
        return dict((nsx_device_id,
                     networkgw_db.STATUS_ACTIVE if connected
                     else networkgw_db.STATUS_DOWN) for
                    (nsx_device_id, connected) in status_dict.iteritems())
    except api_exc.NsxApiException:
        # Do not make a NSX API exception fatal
        if tenant_id:
            LOG.warn(_("Unable to retrieve operational status for gateway "
                       "devices belonging to tenant: %s"), tenant_id)
        else:
            LOG.warn(_("Unable to retrieve operational status for "
                       "gateway devices"))


def _convert_bindings_to_nsx_transport_zones(bindings):
    nsx_transport_zones_config = []
    for binding in bindings:
        transport_entry = {}
        if binding.binding_type in [vmw_utils.NetworkTypes.FLAT,
                                    vmw_utils.NetworkTypes.VLAN]:
            transport_entry['transport_type'] = (
                vmw_utils.NetworkTypes.BRIDGE)
            transport_entry['binding_config'] = {}
            vlan_id = binding.vlan_id
            if vlan_id:
                transport_entry['binding_config'] = (
                    {'vlan_translation': [{'transport': vlan_id}]})
        else:
            transport_entry['transport_type'] = binding.binding_type
        transport_entry['zone_uuid'] = binding.phy_uuid
        nsx_transport_zones_config.append(transport_entry)
    return nsx_transport_zones_config


def _convert_segments_to_nsx_transport_zones(segments, default_tz_uuid):
    nsx_transport_zones_config = []
    for transport_zone in segments:
        for value in [pnet.NETWORK_TYPE, pnet.PHYSICAL_NETWORK,
                      pnet.SEGMENTATION_ID]:
            if transport_zone.get(value) == attr.ATTR_NOT_SPECIFIED:
                transport_zone[value] = None

        transport_entry = {}
        transport_type = transport_zone.get(pnet.NETWORK_TYPE)
        if transport_type in [vmw_utils.NetworkTypes.FLAT,
                              vmw_utils.NetworkTypes.VLAN]:
            transport_entry['transport_type'] = (
                vmw_utils.NetworkTypes.BRIDGE)
            transport_entry['binding_config'] = {}
            vlan_id = transport_zone.get(pnet.SEGMENTATION_ID)
            if vlan_id:
                transport_entry['binding_config'] = (
                    {'vlan_translation': [{'transport': vlan_id}]})
        else:
            transport_entry['transport_type'] = transport_type
        transport_entry['zone_uuid'] = (
            transport_zone[pnet.PHYSICAL_NETWORK] or default_tz_uuid)
        nsx_transport_zones_config.append(transport_entry)
    return nsx_transport_zones_config


def convert_to_nsx_transport_zones(
    default_tz_uuid, network=None, bindings=None,
    default_transport_type=None):

    # Convert fields from provider request to nsx format
    if (network and not attr.is_attr_set(
        network.get(mpnet.SEGMENTS))):
        return [{"zone_uuid": default_tz_uuid,
                 "transport_type": default_transport_type}]

    # Convert fields from db to nsx format
    if bindings:
        return _convert_bindings_to_nsx_transport_zones(bindings)

    # If we end up here we need to convert multiprovider segments into nsx
    # transport zone configurations
    return _convert_segments_to_nsx_transport_zones(
        network.get(mpnet.SEGMENTS), default_tz_uuid)
