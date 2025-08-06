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
import collections

from neutron_lib.api.definitions import allowedaddresspairs as addr_apidef
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api import validators
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.db import api as db_api
from neutron_lib.db import resource_extend
from neutron_lib.db import utils as db_utils
from neutron_lib.exceptions import allowedaddresspairs as addr_exc
from neutron_lib.objects import exceptions
from neutron_lib.utils import net as net_utils

from neutron.objects.port.extensions import (allowedaddresspairs
                                             as obj_addr_pair)


@resource_extend.has_resource_extenders
class AllowedAddressPairsMixin(object):
    """Mixin class for allowed address pairs."""

    def _process_create_allowed_address_pairs(self, context, port,
                                              allowed_address_pairs):
        if not validators.is_attr_set(allowed_address_pairs):
            return []

        desired_state = {
            'context': context,
            'network_id': port['network_id'],
            'allowed_address_pairs': allowed_address_pairs,
        }
        # TODO(slaweq): use constant from neutron_lib.callbacks.resources once
        # it will be available and released
        registry.publish(
            'allowed_address_pair', events.BEFORE_CREATE, self,
            payload=events.DBEventPayload(
                context,
                resource_id=port['id'],
                desired_state=desired_state))
        try:
            with db_api.CONTEXT_WRITER.using(context):
                for address_pair in allowed_address_pairs:
                    # use port.mac_address if no mac address in address pair
                    if 'mac_address' not in address_pair:
                        address_pair['mac_address'] = port['mac_address']
                    # retain string format as passed through API
                    mac_address = net_utils.AuthenticEUI(
                        address_pair['mac_address'])
                    ip_address = net_utils.AuthenticIPNetwork(
                        address_pair['ip_address'])
                    pair_obj = obj_addr_pair.AllowedAddressPair(
                        context,
                        port_id=port['id'],
                        mac_address=mac_address,
                        ip_address=ip_address)
                    pair_obj.create()
        except exceptions.NeutronDbObjectDuplicateEntry:
            raise addr_exc.DuplicateAddressPairInRequest(
                mac_address=address_pair['mac_address'],
                ip_address=address_pair['ip_address'])

        return allowed_address_pairs

    def get_allowed_address_pairs(self, context, port_id):
        pairs = obj_addr_pair.AllowedAddressPair.get_objects(
            context, port_id=port_id)
        return [self._make_allowed_address_pairs_dict(pair.db_obj)
                for pair in pairs]

    def get_allowed_address_pairs_for_ports(self, context, port_ids):
        pairs = (
            obj_addr_pair.AllowedAddressPair.
            get_allowed_address_pairs_for_ports(
                context, port_ids=port_ids))
        result = collections.defaultdict(list)
        for pair in pairs:
            result[pair.port_id].append(
                self._make_allowed_address_pairs_dict(pair.db_obj))
        return result

    @staticmethod
    @resource_extend.extends([port_def.COLLECTION_NAME])
    def _extend_port_dict_allowed_address_pairs(port_res, port_db):
        # If port_db is provided, allowed address pairs will be accessed via
        # sqlalchemy models. As they're loaded together with ports this
        # will not cause an extra query.
        allowed_address_pairs = [
            AllowedAddressPairsMixin._make_allowed_address_pairs_dict(
                address_pair) for
            address_pair in port_db.allowed_address_pairs]
        port_res[addr_apidef.ADDRESS_PAIRS] = allowed_address_pairs
        return port_res

    def _delete_allowed_address_pairs(self, context, id):
        obj_addr_pair.AllowedAddressPair.delete_objects(
            context, port_id=id)

    @staticmethod
    def _make_allowed_address_pairs_dict(allowed_address_pairs,
                                         fields=None):
        res = {'mac_address': allowed_address_pairs['mac_address'],
               'ip_address': allowed_address_pairs['ip_address']}
        return db_utils.resource_fields(res, fields)

    def _has_address_pairs(self, port):
        return (validators.is_attr_set(
            port['port'][addr_apidef.ADDRESS_PAIRS]) and
                port['port'][addr_apidef.ADDRESS_PAIRS] != [])

    def _check_update_has_allowed_address_pairs(self, port):
        """Determine if request has an allowed address pair.

        Return True if the port parameter has a non-empty
        'allowed_address_pairs' attribute. Otherwise returns False.
        """
        return (addr_apidef.ADDRESS_PAIRS in port['port'] and
                self._has_address_pairs(port))

    def _check_update_deletes_allowed_address_pairs(self, port):
        """Determine if request deletes address pair.

        Return True if port has an allowed address pair and its value
        is either [] or not is_attr_set, otherwise return False
        """
        return (addr_apidef.ADDRESS_PAIRS in port['port'] and
                not self._has_address_pairs(port))

    def is_address_pairs_attribute_updated(self, port, update_attrs):
        """Check if the address pairs attribute is being updated.

        Returns True if there is an update. This can be used to decide
        if a port update notification should be sent to agents or third
        party controllers.
        """

        new_pairs = update_attrs.get(addr_apidef.ADDRESS_PAIRS)
        if new_pairs is None:
            return False
        old_pairs = port.get(addr_apidef.ADDRESS_PAIRS)

        # Missing or unchanged address pairs in attributes mean no update
        return new_pairs != old_pairs

    def update_address_pairs_on_port(self, context, port_id, port,
                                     original_port, updated_port):
        """Update allowed address pairs on port.

        Returns True if an update notification is required. Notification
        is not done here because other changes on the port may need
        notification. This method is expected to be called within
        a transaction.
        """
        new_pairs = port['port'].get(addr_apidef.ADDRESS_PAIRS)

        if self.is_address_pairs_attribute_updated(original_port,
                                                   port['port']):
            updated_port[addr_apidef.ADDRESS_PAIRS] = new_pairs
            self._delete_allowed_address_pairs(context, port_id)
            self._process_create_allowed_address_pairs(
                context, updated_port, new_pairs)
            return True

        return False
