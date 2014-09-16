# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

from oslo.db import exception as db_exc
import sqlalchemy as sa
from sqlalchemy.orm import exc as sql_exc

from neutron.common import exceptions
from neutron.db import model_base
from neutron.db import models_v2
from neutron.db.vpn import vpn_db
from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)

# Note: Artificially limit these to reduce mapping table size and performance
# Tunnel can be 0..7FFFFFFF, IKE policy can be 1..10000, IPSec policy can be
# 1..31 characters long.
MAX_CSR_TUNNELS = 10000
MAX_CSR_IKE_POLICIES = 2000
MAX_CSR_IPSEC_POLICIES = 2000

TUNNEL = 'Tunnel'
IKE_POLICY = 'IKE Policy'
IPSEC_POLICY = 'IPSec Policy'

MAPPING_LIMITS = {TUNNEL: (0, MAX_CSR_TUNNELS),
                  IKE_POLICY: (1, MAX_CSR_IKE_POLICIES),
                  IPSEC_POLICY: (1, MAX_CSR_IPSEC_POLICIES)}


class CsrInternalError(exceptions.NeutronException):
    message = _("Fatal - %(reason)s")


class IdentifierMap(model_base.BASEV2, models_v2.HasTenant):

    """Maps OpenStack IDs to compatible numbers for Cisco CSR."""

    __tablename__ = 'cisco_csr_identifier_map'

    ipsec_site_conn_id = sa.Column(sa.String(64),
                                   sa.ForeignKey('ipsec_site_connections.id',
                                                 ondelete="CASCADE"),
                                   primary_key=True)
    csr_tunnel_id = sa.Column(sa.Integer, nullable=False)
    csr_ike_policy_id = sa.Column(sa.Integer, nullable=False)
    csr_ipsec_policy_id = sa.Column(sa.Integer, nullable=False)


def get_next_available_id(session, table_field, id_type):
    """Find first unused id for the specified field in IdentifierMap table.

    As entries are removed, find the first "hole" and return that as the
    next available ID. To improve performance, artificially limit
    the number of entries to a smaller range. Currently, these IDs are
    globally unique. Could enhance in the future to be unique per router
    (CSR).
    """
    min_value = MAPPING_LIMITS[id_type][0]
    max_value = MAPPING_LIMITS[id_type][1]
    rows = session.query(table_field).order_by(table_field)
    used_ids = set([row[0] for row in rows])
    all_ids = set(range(min_value, max_value + min_value))
    available_ids = all_ids - used_ids
    if not available_ids:
        msg = _("No available Cisco CSR %(type)s IDs from "
                "%(min)d..%(max)d") % {'type': id_type,
                                       'min': min_value,
                                       'max': max_value}
        LOG.error(msg)
        raise IndexError(msg)
    return available_ids.pop()


def get_next_available_tunnel_id(session):
    """Find first available tunnel ID from 0..MAX_CSR_TUNNELS-1."""
    return get_next_available_id(session, IdentifierMap.csr_tunnel_id,
                                 TUNNEL)


def get_next_available_ike_policy_id(session):
    """Find first available IKE Policy ID from 1..MAX_CSR_IKE_POLICIES."""
    return get_next_available_id(session, IdentifierMap.csr_ike_policy_id,
                                 IKE_POLICY)


def get_next_available_ipsec_policy_id(session):
    """Find first available IPSec Policy ID from 1..MAX_CSR_IKE_POLICIES."""
    return get_next_available_id(session, IdentifierMap.csr_ipsec_policy_id,
                                 IPSEC_POLICY)


def find_conn_with_policy(policy_field, policy_id, conn_id, session):
    """Return ID of another conneciton (if any) that uses same policy ID."""
    qry = session.query(vpn_db.IPsecSiteConnection.id)
    match = qry.filter_request(
        policy_field == policy_id,
        vpn_db.IPsecSiteConnection.id != conn_id).first()
    if match:
        return match[0]


def find_connection_using_ike_policy(ike_policy_id, conn_id, session):
    """Return ID of another connection that uses same IKE policy ID."""
    return find_conn_with_policy(vpn_db.IPsecSiteConnection.ikepolicy_id,
                                 ike_policy_id, conn_id, session)


def find_connection_using_ipsec_policy(ipsec_policy_id, conn_id, session):
    """Return ID of another connection that uses same IPSec policy ID."""
    return find_conn_with_policy(vpn_db.IPsecSiteConnection.ipsecpolicy_id,
                                 ipsec_policy_id, conn_id, session)


def lookup_policy(policy_type, policy_field, conn_id, session):
    """Obtain specified policy's mapping from other connection."""
    try:
        return session.query(policy_field).filter_by(
            ipsec_site_conn_id=conn_id).one()[0]
    except sql_exc.NoResultFound:
        msg = _("Database inconsistency between IPSec connection and "
                "Cisco CSR mapping table (%s)") % policy_type
        raise CsrInternalError(reason=msg)


def lookup_ike_policy_id_for(conn_id, session):
    """Obtain existing Cisco CSR IKE policy ID from another connection."""
    return lookup_policy(IKE_POLICY, IdentifierMap.csr_ike_policy_id,
                         conn_id, session)


def lookup_ipsec_policy_id_for(conn_id, session):
    """Obtain existing Cisco CSR IPSec policy ID from another connection."""
    return lookup_policy(IPSEC_POLICY, IdentifierMap.csr_ipsec_policy_id,
                         conn_id, session)


def determine_csr_policy_id(policy_type, conn_policy_field, map_policy_field,
                            policy_id, conn_id, session):
    """Use existing or reserve a new policy ID for Cisco CSR use.

    TODO(pcm) FUTURE: Once device driver adds support for IKE/IPSec policy
    ID sharing, add call to find_conn_with_policy() to find used ID and
    then call lookup_policy() to find the current mapping for that ID.
    """
    csr_id = get_next_available_id(session, map_policy_field, policy_type)
    LOG.debug(_("Reserved new CSR ID %(csr_id)d for %(policy)s "
                "ID %(policy_id)s"), {'csr_id': csr_id,
                                      'policy': policy_type,
                                      'policy_id': policy_id})
    return csr_id


def determine_csr_ike_policy_id(ike_policy_id, conn_id, session):
    """Use existing, or reserve a new IKE policy ID for Cisco CSR."""
    return determine_csr_policy_id(IKE_POLICY,
                                   vpn_db.IPsecSiteConnection.ikepolicy_id,
                                   IdentifierMap.csr_ike_policy_id,
                                   ike_policy_id, conn_id, session)


def determine_csr_ipsec_policy_id(ipsec_policy_id, conn_id, session):
    """Use existing, or reserve a new IPSec policy ID for Cisco CSR."""
    return determine_csr_policy_id(IPSEC_POLICY,
                                   vpn_db.IPsecSiteConnection.ipsecpolicy_id,
                                   IdentifierMap.csr_ipsec_policy_id,
                                   ipsec_policy_id, conn_id, session)


def get_tunnel_mapping_for(conn_id, session):
    try:
        entry = session.query(IdentifierMap).filter_by(
            ipsec_site_conn_id=conn_id).one()
        LOG.debug(_("Mappings for IPSec connection %(conn)s - "
                    "tunnel=%(tunnel)s ike_policy=%(csr_ike)d "
                    "ipsec_policy=%(csr_ipsec)d"),
                  {'conn': conn_id, 'tunnel': entry.csr_tunnel_id,
                   'csr_ike': entry.csr_ike_policy_id,
                   'csr_ipsec': entry.csr_ipsec_policy_id})
        return (entry.csr_tunnel_id, entry.csr_ike_policy_id,
                entry.csr_ipsec_policy_id)
    except sql_exc.NoResultFound:
        msg = _("Existing entry for IPSec connection %s not found in Cisco "
                "CSR mapping table") % conn_id
        raise CsrInternalError(reason=msg)


def create_tunnel_mapping(context, conn_info):
    """Create Cisco CSR IDs, using mapping table and OpenStack UUIDs."""
    conn_id = conn_info['id']
    ike_policy_id = conn_info['ikepolicy_id']
    ipsec_policy_id = conn_info['ipsecpolicy_id']
    tenant_id = conn_info['tenant_id']
    with context.session.begin():
        csr_tunnel_id = get_next_available_tunnel_id(context.session)
        csr_ike_id = determine_csr_ike_policy_id(ike_policy_id, conn_id,
                                                 context.session)
        csr_ipsec_id = determine_csr_ipsec_policy_id(ipsec_policy_id, conn_id,
                                                     context.session)
        map_entry = IdentifierMap(tenant_id=tenant_id,
                                  ipsec_site_conn_id=conn_id,
                                  csr_tunnel_id=csr_tunnel_id,
                                  csr_ike_policy_id=csr_ike_id,
                                  csr_ipsec_policy_id=csr_ipsec_id)
        try:
            context.session.add(map_entry)
            # Force committing to database
            context.session.flush()
        except db_exc.DBDuplicateEntry:
            msg = _("Attempt to create duplicate entry in Cisco CSR "
                    "mapping table for connection %s") % conn_id
            raise CsrInternalError(reason=msg)
        LOG.info(_("Mapped connection %(conn_id)s to Tunnel%(tunnel_id)d "
                   "using IKE policy ID %(ike_id)d and IPSec policy "
                   "ID %(ipsec_id)d"),
                 {'conn_id': conn_id, 'tunnel_id': csr_tunnel_id,
                  'ike_id': csr_ike_id, 'ipsec_id': csr_ipsec_id})


def delete_tunnel_mapping(context, conn_info):
    conn_id = conn_info['id']
    with context.session.begin():
        sess_qry = context.session.query(IdentifierMap)
        sess_qry.filter_by(ipsec_site_conn_id=conn_id).delete()
    LOG.info(_("Removed mapping for connection %s"), conn_id)
