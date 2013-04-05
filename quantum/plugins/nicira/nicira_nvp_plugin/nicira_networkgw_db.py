# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Nicira Networks, Inc.  All rights reserved.
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
# @author: Salvatore Orlando, VMware
#

import sqlalchemy as sa

from sqlalchemy import orm
from sqlalchemy.orm import exc as sa_orm_exc
from webob import exc as web_exc

from quantum.api.v2 import attributes
from quantum.api.v2 import base
from quantum.common import exceptions
from quantum.db import db_base_plugin_v2
from quantum.db import model_base
from quantum.db import models_v2
from quantum.openstack.common import log as logging
from quantum.openstack.common import uuidutils
from quantum.plugins.nicira.nicira_nvp_plugin.extensions import nvp_networkgw


LOG = logging.getLogger(__name__)
DEVICE_OWNER_NET_GW_INTF = 'network:gateway-interface'
NETWORK_ID = 'network_id'
SEGMENTATION_TYPE = 'segmentation_type'
SEGMENTATION_ID = 'segmentation_id'
ALLOWED_CONNECTION_ATTRIBUTES = set((NETWORK_ID,
                                     SEGMENTATION_TYPE,
                                     SEGMENTATION_ID))


class GatewayInUse(exceptions.InUse):
    message = _("Network Gateway '%(gateway_id)s' still has active mappings "
                "with one or more quantum networks.")


class NetworkGatewayPortInUse(exceptions.InUse):
    message = _("Port '%(port_id)s' is owned by '%(device_owner)s' and "
                "therefore cannot be deleted directly via the port API.")


class GatewayConnectionInUse(exceptions.InUse):
    message = _("The specified mapping '%(mapping)s' is already in use on "
                "network gateway '%(gateway_id)s'.")


class MultipleGatewayConnections(exceptions.QuantumException):
    message = _("Multiple network connections found on '%(gateway_id)s' "
                "with provided criteria.")


class GatewayConnectionNotFound(exceptions.NotFound):
    message = _("The connection %(network_mapping_info)s was not found on the "
                "network gateway '%(network_gateway_id)s'")


class NetworkGatewayUnchangeable(exceptions.InUse):
    message = _("The network gateway %(gateway_id)s "
                "cannot be updated or deleted")

# Add exceptions to HTTP Faults mappings
base.FAULT_MAP.update({GatewayInUse: web_exc.HTTPConflict,
                       NetworkGatewayPortInUse: web_exc.HTTPConflict,
                       GatewayConnectionInUse: web_exc.HTTPConflict,
                       GatewayConnectionNotFound: web_exc.HTTPNotFound,
                       MultipleGatewayConnections: web_exc.HTTPConflict})


class NetworkConnection(model_base.BASEV2, models_v2.HasTenant):
    """ Defines a connection between a network gateway and a network """
    # We use port_id as the primary key as one can connect a gateway
    # to a network in multiple ways (and we cannot use the same port form
    # more than a single gateway)
    network_gateway_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('networkgateways.id',
                                                 ondelete='CASCADE'))
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete='CASCADE'))
    segmentation_type = sa.Column(
        sa.Enum('flat', 'vlan',
                name='networkconnections_segmentation_type'))
    segmentation_id = sa.Column(sa.Integer)
    __table_args__ = (sa.UniqueConstraint(network_gateway_id,
                                          segmentation_type,
                                          segmentation_id),)
    # Also, storing port id comes back useful when disconnecting a network
    # from a gateway
    port_id = sa.Column(sa.String(36),
                        sa.ForeignKey('ports.id', ondelete='CASCADE'),
                        primary_key=True)


class NetworkGatewayDevice(model_base.BASEV2):
    id = sa.Column(sa.String(36), primary_key=True)
    network_gateway_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('networkgateways.id',
                                                 ondelete='CASCADE'))
    interface_name = sa.Column(sa.String(64))


class NetworkGateway(model_base.BASEV2, models_v2.HasId,
                     models_v2.HasTenant):
    """ Defines the data model for a network gateway """
    name = sa.Column(sa.String(255))
    # Tenant id is nullable for this resource
    tenant_id = sa.Column(sa.String(36))
    default = sa.Column(sa.Boolean())
    devices = orm.relationship(NetworkGatewayDevice,
                               backref='networkgateways',
                               cascade='all,delete')
    network_connections = orm.relationship(NetworkConnection)


class NetworkGatewayMixin(nvp_networkgw.NetworkGatewayPluginBase):

    resource = nvp_networkgw.RESOURCE_NAME.replace('-', '_')

    def _get_network_gateway(self, context, gw_id):
        return self._get_by_id(context, NetworkGateway, gw_id)

    def _make_network_gateway_dict(self, network_gateway, fields=None):
        device_list = []
        for d in network_gateway['devices']:
            device_list.append({'id': d['id'],
                                'interface_name': d['interface_name']})
        res = {'id': network_gateway['id'],
               'name': network_gateway['name'],
               'default': network_gateway['default'],
               'devices': device_list,
               'tenant_id': network_gateway['tenant_id']}
        # NOTE(salvatore-orlando):perhaps return list of connected networks
        return self._fields(res, fields)

    def _validate_network_mapping_info(self, network_mapping_info):
        network_id = network_mapping_info.get(NETWORK_ID)
        if not network_id:
            raise exceptions.InvalidInput(
                error_message=_("A network identifier must be specified "
                                "when connecting a network to a network "
                                "gateway. Unable to complete operation"))
        connection_attrs = set(network_mapping_info.keys())
        if not connection_attrs.issubset(ALLOWED_CONNECTION_ATTRIBUTES):
            raise exceptions.InvalidInput(
                error_message=(_("Invalid keys found among the ones provided "
                                 "in request body: %(connection_attrs)s."),
                               connection_attrs))
        seg_type = network_mapping_info.get(SEGMENTATION_TYPE)
        seg_id = network_mapping_info.get(SEGMENTATION_ID)
        if not seg_type and seg_id:
            msg = _("In order to specify a segmentation id the "
                    "segmentation type must be specified as well")
            raise exceptions.InvalidInput(error_message=msg)
        elif seg_type and seg_type.lower() == 'flat' and seg_id:
            msg = _("Cannot specify a segmentation id when "
                    "the segmentation type is flat")
            raise exceptions.InvalidInput(error_message=msg)
        return network_id

    def _retrieve_gateway_connections(self, context, gateway_id, mapping_info,
                                      only_one=False):
        filters = {'network_gateway_id': [gateway_id]}
        for k, v in mapping_info.iteritems():
            if v and k != NETWORK_ID:
                filters[k] = [v]
        query = self._get_collection_query(context,
                                           NetworkConnection,
                                           filters)
        return only_one and query.one() or query.all()

    def _unset_default_network_gateways(self, context):
        with context.session.begin(subtransactions=True):
            context.session.query(NetworkGateway).update(
                {NetworkGateway.default: False})

    def _set_default_network_gateway(self, context, gw_id):
        with context.session.begin(subtransactions=True):
            gw = (context.session.query(NetworkGateway).
                  filter_by(id=gw_id).one())
            gw['default'] = True

    def prevent_network_gateway_port_deletion(self, context, port):
        """ Pre-deletion check.

        Ensures a port will not be deleted if is being used by a network
        gateway. In that case an exception will be raised.
        """
        if port['device_owner'] == DEVICE_OWNER_NET_GW_INTF:
            raise NetworkGatewayPortInUse(port_id=port['id'],
                                          device_owner=port['device_owner'])

    def create_network_gateway(self, context, network_gateway):
        gw_data = network_gateway[self.resource]
        tenant_id = self._get_tenant_id_for_create(context, gw_data)
        with context.session.begin(subtransactions=True):
            gw_db = NetworkGateway(
                id=gw_data.get('id', uuidutils.generate_uuid()),
                tenant_id=tenant_id,
                name=gw_data.get('name'))
            # Device list is guaranteed to be a valid list
            gw_db.devices.extend([NetworkGatewayDevice(**device)
                                  for device in gw_data['devices']])
            context.session.add(gw_db)
        LOG.debug(_("Created network gateway with id:%s"), gw_db['id'])
        return self._make_network_gateway_dict(gw_db)

    def update_network_gateway(self, context, id, network_gateway):
        gw_data = network_gateway[self.resource]
        with context.session.begin(subtransactions=True):
            gw_db = self._get_network_gateway(context, id)
            if gw_db.default:
                raise NetworkGatewayUnchangeable(gateway_id=id)
            # Ensure there is something to update before doing it
            db_values_set = set([v for (k, v) in gw_db.iteritems()])
            if not set(gw_data.values()).issubset(db_values_set):
                gw_db.update(gw_data)
        LOG.debug(_("Updated network gateway with id:%s"), id)
        return self._make_network_gateway_dict(gw_db)

    def get_network_gateway(self, context, id, fields=None):
        gw_db = self._get_network_gateway(context, id)
        return self._make_network_gateway_dict(gw_db, fields)

    def delete_network_gateway(self, context, id):
        with context.session.begin(subtransactions=True):
            gw_db = self._get_network_gateway(context, id)
            if gw_db.network_connections:
                raise GatewayInUse(gateway_id=id)
            if gw_db.default:
                raise NetworkGatewayUnchangeable(gateway_id=id)
            context.session.delete(gw_db)
        LOG.debug(_("Network gateway '%s' was destroyed."), id)

    def get_network_gateways(self, context, filters=None, fields=None):
        return self._get_collection(context, NetworkGateway,
                                    self._make_network_gateway_dict,
                                    filters=filters, fields=fields)

    def connect_network(self, context, network_gateway_id,
                        network_mapping_info):
        network_id = self._validate_network_mapping_info(network_mapping_info)
        LOG.debug(_("Connecting network '%(network_id)s' to gateway "
                    "'%(network_gateway_id)s'"),
                  {'network_id': network_id,
                   'network_gateway_id': network_gateway_id})
        with context.session.begin(subtransactions=True):
            gw_db = self._get_network_gateway(context, network_gateway_id)
            tenant_id = self._get_tenant_id_for_create(context, gw_db)
            # TODO(salvatore-orlando): Leverage unique constraint instead
            # of performing another query!
            if self._retrieve_gateway_connections(context,
                                                  network_gateway_id,
                                                  network_mapping_info):
                raise GatewayConnectionInUse(mapping=network_mapping_info,
                                             gateway_id=network_gateway_id)
            # TODO(salvatore-orlando): This will give the port a fixed_ip,
            # but we actually do not need any. Instead of wasting an IP we
            # should have a way to say a port shall not be associated with
            # any subnet
            try:
                # We pass the segmentation type and id too - the plugin
                # might find them useful as the network connection object
                # does not exist yet.
                # NOTE: they're not extended attributes, rather extra data
                # passed in the port structure to the plugin
                # TODO(salvatore-orlando): Verify optimal solution for
                # ownership of the gateway port
                port = self.create_port(context, {
                    'port':
                    {'tenant_id': tenant_id,
                     'network_id': network_id,
                     'mac_address': attributes.ATTR_NOT_SPECIFIED,
                     'admin_state_up': True,
                     'fixed_ips': [],
                     'device_id': network_gateway_id,
                     'device_owner': DEVICE_OWNER_NET_GW_INTF,
                     'name': '',
                     'gw:segmentation_type':
                     network_mapping_info.get('segmentation_type'),
                     'gw:segmentation_id':
                     network_mapping_info.get('segmentation_id')}})
            except exceptions.NetworkNotFound:
                err_msg = (_("Requested network '%(network_id)s' not found."
                             "Unable to create network connection on "
                             "gateway '%(network_gateway_id)s") %
                           {'network_id': network_id,
                            'network_gateway_id': network_gateway_id})
                LOG.error(err_msg)
                raise exceptions.InvalidInput(error_message=err_msg)
            port_id = port['id']
            LOG.debug(_("Gateway port for '%(network_gateway_id)s' "
                        "created on network '%(network_id)s':%(port_id)s"),
                      {'network_gateway_id': network_gateway_id,
                       'network_id': network_id,
                       'port_id': port_id})
            # Create NetworkConnection record
            network_mapping_info['port_id'] = port_id
            network_mapping_info['tenant_id'] = tenant_id
            gw_db.network_connections.append(
                NetworkConnection(**network_mapping_info))
            port_id = port['id']
            # now deallocate the ip from the port
            for fixed_ip in port.get('fixed_ips', []):
                db_base_plugin_v2.QuantumDbPluginV2._delete_ip_allocation(
                    context, network_id,
                    fixed_ip['subnet_id'],
                    fixed_ip['ip_address'])
            LOG.debug(_("Ensured no Ip addresses are configured on port %s"),
                      port_id)
            return {'connection_info':
                    {'network_gateway_id': network_gateway_id,
                     'network_id': network_id,
                     'port_id': port_id}}

    def disconnect_network(self, context, network_gateway_id,
                           network_mapping_info):
        network_id = self._validate_network_mapping_info(network_mapping_info)
        LOG.debug(_("Disconnecting network '%(network_id)s' from gateway "
                    "'%(network_gateway_id)s'"),
                  {'network_id': network_id,
                   'network_gateway_id': network_gateway_id})
        with context.session.begin(subtransactions=True):
            # Uniquely identify connection, otherwise raise
            try:
                net_connection = self._retrieve_gateway_connections(
                    context, network_gateway_id,
                    network_mapping_info, only_one=True)
            except sa_orm_exc.NoResultFound:
                raise GatewayConnectionNotFound(
                    network_mapping_info=network_mapping_info,
                    network_gateway_id=network_gateway_id)
            except sa_orm_exc.MultipleResultsFound:
                raise MultipleGatewayConnections(
                    gateway_id=network_gateway_id)
            # Remove gateway port from network
            # FIXME(salvatore-orlando): Ensure state of port in NVP is
            # consistent with outcome of transaction
            self.delete_port(context, net_connection['port_id'],
                             nw_gw_port_check=False)
            # Remove NetworkConnection record
            context.session.delete(net_connection)
