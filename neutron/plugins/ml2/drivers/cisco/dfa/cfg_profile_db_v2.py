# Copyright 2014 Cisco Systems, Inc.
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
#


from sqlalchemy.orm import exc

from neutron.db import models_v2
from neutron.plugins.ml2.drivers.cisco.dfa import constants as dfac
from neutron.plugins.ml2.drivers.cisco.dfa import dfa_exceptions as dexc
from neutron.plugins.ml2.drivers.cisco.dfa import dfa_models_v2


def get_network_profile_binding(session, net_id):
    """Retrieve network and config profile binding."""

    try:
        return (session.query(dfa_models_v2.ConfigProfileBinding).
                filter_by(network_id=net_id).one())
    except (exc.NoResultFound, exc.MultipleResultsFound):
        pass


def add_dfa_cfg_profile_binding(session, netid, cpid):
    """Add new entry to the config profile binding database."""

    try:
        if cpid == dfac.DEFAULT_CFG_PROFILE_ID:
            # The config profile is not provided when creating network.
            # Use 'defaultNetworkL2Profile' as default config profile.
            cfgp_name = 'defaultNetworkL2Profile'
            cfgp_entry = (session.query(dfa_models_v2.ConfigProfile).
                          filter_by(name=cfgp_name).one())
            cpid = cfgp_entry.id

        binding = dfa_models_v2.ConfigProfileBinding(network_id=netid,
                                                     cfg_profile_id=cpid)
        session.add(binding)
    except (exc.NoResultFound, exc.MultipleResultsFound):
        raise dexc.ConfigProfileNotFound(network_id=netid)


def get_network_entry(session, netid):
    """Retrieve network information."""

    try:
        return (session.query(models_v2.Network).
                filter_by(id=netid).one())
    except (exc.NoResultFound, exc.MultipleResultsFound):
        raise dexc.NetworkNotFound(network_id=netid)


def get_config_profile_name(db_session, netid):
    """Retrieve configuration profile for a network."""

    try:
        cfgpobj = dfa_models_v2.ConfigProfileBinding
        cfgp = db_session.query(cfgpobj).filter_by(network_id=netid).one()
        cfgid = cfgp.cfg_profile_id
    except (exc.NoResultFound, exc.MultipleResultsFound):
        raise dexc.ConfigProfileNotFound(network_id=netid)
    try:
        cfgp_entry = db_session.query(
            dfa_models_v2.ConfigProfile).filter_by(id=cfgid).one()
    except (exc.NoResultFound, exc.MultipleResultsFound):
        raise dexc.ConfigProfileIdNotFound(profile_id=cfgid)
    return cfgp_entry.name


def get_config_profile_fwd_mode(db_session, network_id):
    """Retrieve configuration profile for a network."""

    try:
        cfgp = (db_session.query(dfa_models_v2.ConfigProfileBinding).
            filter_by(network_id=network_id).one())
        cfgid = cfgp.cfg_profile_id
    except (exc.NoResultFound, exc.MultipleResultsFound):
        raise dexc.ConfigProfileNotFound(network_id=network_id)

    try:
        cfgp_entry = db_session.query(
            dfa_models_v2.ConfigProfile).filter_by(id=cfgid).one()
        return cfgp_entry.forwarding_mode
    except (exc.NoResultFound, exc.MultipleResultsFound):
        raise dexc.ConfigProfileIdNotFound(profile_id=cfgid)


def delete_dfa_cfg_profile_binding(db_session, network_id):
    """Delete an entry from the config profile binding database."""

    try:
        with db_session.begin(subtransactions=True):
            entry = (db_session.query(dfa_models_v2.ConfigProfileBinding).
                     filter_by(network_id=network_id).one())
            db_session.delete(entry)
    except (exc.NoResultFound, exc.MultipleResultsFound):
        raise dexc.ConfigProfileNotFound(network_id=network_id)
