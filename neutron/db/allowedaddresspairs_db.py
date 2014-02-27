# Copyright 2013 VMware, Inc.  All rights reserved.
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

import sqlalchemy as sa
from sqlalchemy import orm

from neutron.api.v2 import attributes as attr
from neutron.common import utils
from neutron.db import db_base_plugin_v2
from neutron.db import model_base
from neutron.db import models_v2
from neutron.extensions import allowedaddresspairs as addr_pair


class AllowedAddressPair(model_base.BASEV2):
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete="CASCADE"),
                        primary_key=True)
    mac_address = sa.Column(sa.String(32), nullable=False, primary_key=True)
    ip_address = sa.Column(sa.String(64), nullable=False, primary_key=True)

    port = orm.relationship(
        models_v2.Port,
        backref=orm.backref("allowed_address_pairs",
                            lazy="joined", cascade="delete"))


class AllowedAddressPairsMixin(object):
    """Mixin class for allowed address pairs."""

    def _process_create_allowed_address_pairs(self, context, port,
                                              allowed_address_pairs):
        if not attr.is_attr_set(allowed_address_pairs):
            return []
        with context.session.begin(subtransactions=True):
            for address_pair in allowed_address_pairs:
                # use port.mac_address if no mac address in address pair
                if 'mac_address' not in address_pair:
                    address_pair['mac_address'] = port['mac_address']
                for fixed_ip in port['fixed_ips']:
                    if ((fixed_ip['ip_address'] == address_pair['ip_address'])
                        and (port['mac_address'] ==
                             address_pair['mac_address'])):
                        raise addr_pair.AddressPairMatchesPortFixedIPAndMac()
                db_pair = AllowedAddressPair(
                    port_id=port['id'],
                    mac_address=address_pair['mac_address'],
                    ip_address=address_pair['ip_address'])
                context.session.add(db_pair)

        return allowed_address_pairs

    def _check_fixed_ips_and_address_pairs_no_overlap(self, context, port):
        address_pairs = self.get_allowed_address_pairs(context, port['id'])
        for fixed_ip in port['fixed_ips']:
            for address_pair in address_pairs:
                if (fixed_ip['ip_address'] == address_pair['ip_address']
                    and port['mac_address'] == address_pair['mac_address']):
                    raise addr_pair.AddressPairMatchesPortFixedIPAndMac()

    def get_allowed_address_pairs(self, context, port_id):
        pairs = (context.session.query(AllowedAddressPair).
                 filter_by(port_id=port_id))
        return [self._make_allowed_address_pairs_dict(pair)
                for pair in pairs]

    def _extend_port_dict_allowed_address_pairs(self, port_res, port_db):
        # If port_db is provided, allowed address pairs will be accessed via
        # sqlalchemy models. As they're loaded together with ports this
        # will not cause an extra query.
        allowed_address_pairs = [
            self._make_allowed_address_pairs_dict(address_pair) for
            address_pair in port_db.allowed_address_pairs]
        port_res[addr_pair.ADDRESS_PAIRS] = allowed_address_pairs
        return port_res

    # Register dict extend functions for ports
    db_base_plugin_v2.NeutronDbPluginV2.register_dict_extend_funcs(
        attr.PORTS, ['_extend_port_dict_allowed_address_pairs'])

    def _delete_allowed_address_pairs(self, context, id):
        query = self._model_query(context, AllowedAddressPair)
        with context.session.begin(subtransactions=True):
            query.filter(AllowedAddressPair.port_id == id).delete()

    def _make_allowed_address_pairs_dict(self, allowed_address_pairs,
                                         fields=None):
        res = {'mac_address': allowed_address_pairs['mac_address'],
               'ip_address': allowed_address_pairs['ip_address']}
        return self._fields(res, fields)

    def _has_address_pairs(self, port):
        return (attr.is_attr_set(port['port'][addr_pair.ADDRESS_PAIRS])
                and port['port'][addr_pair.ADDRESS_PAIRS] != [])

    def _check_update_has_allowed_address_pairs(self, port):
        """Determine if request has an allowed address pair.

        Return True if the port parameter has a non-empty
        'allowed_address_pairs' attribute. Otherwise returns False.
        """
        return (addr_pair.ADDRESS_PAIRS in port['port'] and
                self._has_address_pairs(port))

    def _check_update_deletes_allowed_address_pairs(self, port):
        """Determine if request deletes address pair.

        Return True if port has as a allowed address pair and its value
        is either [] or not is_attr_set, otherwise return False
        """
        return (addr_pair.ADDRESS_PAIRS in port['port'] and
                not self._has_address_pairs(port))

    def is_address_pairs_attribute_updated(self, port, update_attrs):
        """Check if the address pairs attribute is being updated.

        This method returns a flag which indicates whether there is an update
        and therefore a port update notification should be sent to agents or
        third party controllers.
        """
        new_pairs = update_attrs.get(addr_pair.ADDRESS_PAIRS)
        if new_pairs and not utils.compare_elements(
            port.get(addr_pair.ADDRESS_PAIRS), new_pairs):
            return True
        # Missing or unchanged address pairs in attributes mean no update
        return False
