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

import sqlalchemy as sa

from sqlalchemy import orm
from sqlalchemy.orm import exc as sa_orm_exc

from neutron.api.v2 import attributes
from neutron.common import exceptions
from neutron.common import utils
from neutron.db import model_base
from neutron.db import models_v2
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron.plugins.vmware.extensions import networkgw


LOG = logging.getLogger(__name__)
DEVICE_OWNER_NET_GW_INTF = 'network:gateway-interface'
NETWORK_ID = 'network_id'
SEGMENTATION_TYPE = 'segmentation_type'
SEGMENTATION_ID = 'segmentation_id'
ALLOWED_CONNECTION_ATTRIBUTES = set((NETWORK_ID,
                                     SEGMENTATION_TYPE,
                                     SEGMENTATION_ID))
# Constants for gateway device operational status
STATUS_UNKNOWN = "UNKNOWN"
STATUS_ERROR = "ERROR"
STATUS_ACTIVE = "ACTIVE"
STATUS_DOWN = "DOWN"


class GatewayInUse(exceptions.InUse):
    message = _("Network Gateway '%(gateway_id)s' still has active mappings "
                "with one or more neutron networks.")


class GatewayNotFound(exceptions.NotFound):
    message = _("Network Gateway %(gateway_id)s could not be found")


class GatewayDeviceInUse(exceptions.InUse):
    message = _("Network Gateway Device '%(device_id)s' is still used by "
                "one or more network gateways.")


class GatewayDeviceNotFound(exceptions.NotFound):
    message = _("Network Gateway Device %(device_id)s could not be found.")


class NetworkGatewayPortInUse(exceptions.InUse):
    message = _("Port '%(port_id)s' is owned by '%(device_owner)s' and "
                "therefore cannot be deleted directly via the port API.")


class GatewayConnectionInUse(exceptions.InUse):
    message = _("The specified mapping '%(mapping)s' is already in use on "
                "network gateway '%(gateway_id)s'.")


class MultipleGatewayConnections(exceptions.Conflict):
    message = _("Multiple network connections found on '%(gateway_id)s' "
                "with provided criteria.")


class GatewayConnectionNotFound(exceptions.NotFound):
    message = _("The connection %(network_mapping_info)s was not found on the "
                "network gateway '%(network_gateway_id)s'")


class NetworkGatewayUnchangeable(exceptions.InUse):
    message = _("The network gateway %(gateway_id)s "
                "cannot be updated or deleted")


class NetworkConnection(model_base.BASEV2, models_v2.HasTenant):
    """Defines a connection between a network gateway and a network."""
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


class NetworkGatewayDeviceReference(model_base.BASEV2):
    id = sa.Column(sa.String(36), primary_key=True)
    network_gateway_id = sa.Column(sa.String(36),
                                   sa.ForeignKey('networkgateways.id',
                                                 ondelete='CASCADE'),
                                   primary_key=True)
    interface_name = sa.Column(sa.String(64), primary_key=True)


class NetworkGatewayDevice(model_base.BASEV2, models_v2.HasId,
                           models_v2.HasTenant):
    nsx_id = sa.Column(sa.String(36))
    # Optional name for the gateway device
    name = sa.Column(sa.String(255))
    # Transport connector type. Not using enum as range of
    # connector types might vary with backend version
    connector_type = sa.Column(sa.String(10))
    # Transport connector IP Address
    connector_ip = sa.Column(sa.String(64))
    # operational status
    status = sa.Column(sa.String(16))


class NetworkGateway(model_base.BASEV2, models_v2.HasId,
                     models_v2.HasTenant):
    """Defines the data model for a network gateway."""
    name = sa.Column(sa.String(255))
    # Tenant id is nullable for this resource
    tenant_id = sa.Column(sa.String(36))
    default = sa.Column(sa.Boolean())
    devices = orm.relationship(NetworkGatewayDeviceReference,
                               backref='networkgateways',
                               cascade='all,delete')
    network_connections = orm.relationship(NetworkConnection, lazy='joined')


class NetworkGatewayMixin(networkgw.NetworkGatewayPluginBase):

    gateway_resource = networkgw.GATEWAY_RESOURCE_NAME
    device_resource = networkgw.DEVICE_RESOURCE_NAME

    def _get_network_gateway(self, context, gw_id):
        try:
            gw = self._get_by_id(context, NetworkGateway, gw_id)
        except sa_orm_exc.NoResultFound:
            raise GatewayNotFound(gateway_id=gw_id)
        return gw

    def _make_gw_connection_dict(self, gw_conn):
        return {'port_id': gw_conn['port_id'],
                'segmentation_type': gw_conn['segmentation_type'],
                'segmentation_id': gw_conn['segmentation_id']}

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
        # Query gateway connections only if needed
        if (fields and 'ports' in fields) or not fields:
            res['ports'] = [self._make_gw_connection_dict(conn)
                            for conn in network_gateway.network_connections]
        return self._fields(res, fields)

    def _set_mapping_info_defaults(self, mapping_info):
        if not mapping_info.get('segmentation_type'):
            mapping_info['segmentation_type'] = 'flat'
        if not mapping_info.get('segmentation_id'):
            mapping_info['segmentation_id'] = 0

    def _validate_network_mapping_info(self, network_mapping_info):
        self._set_mapping_info_defaults(network_mapping_info)
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
        # The NSX plugin accepts 0 as a valid vlan tag
        seg_id_valid = seg_id == 0 or utils.is_valid_vlan_tag(seg_id)
        if seg_type.lower() == 'flat' and seg_id:
            msg = _("Cannot specify a segmentation id when "
                    "the segmentation type is flat")
            raise exceptions.InvalidInput(error_message=msg)
        elif (seg_type.lower() == 'vlan' and not seg_id_valid):
            msg = _("Invalid segmentation id (%d) for "
                    "vlan segmentation type") % seg_id
            raise exceptions.InvalidInput(error_message=msg)
        return network_id

    def _retrieve_gateway_connections(self, context, gateway_id,
                                      mapping_info={}, only_one=False):
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
        """Pre-deletion check.

        Ensures a port will not be deleted if is being used by a network
        gateway. In that case an exception will be raised.
        """
        if port['device_owner'] == DEVICE_OWNER_NET_GW_INTF:
            raise NetworkGatewayPortInUse(port_id=port['id'],
                                          device_owner=port['device_owner'])

    def create_network_gateway(self, context, network_gateway):
        gw_data = network_gateway[self.gateway_resource]
        tenant_id = self._get_tenant_id_for_create(context, gw_data)
        with context.session.begin(subtransactions=True):
            gw_db = NetworkGateway(
                id=gw_data.get('id', uuidutils.generate_uuid()),
                tenant_id=tenant_id,
                name=gw_data.get('name'))
            # Device list is guaranteed to be a valid list
            device_query = self._query_gateway_devices(
                context, filters={'id': [device['id']
                                         for device in gw_data['devices']]})
            for device in device_query:
                if device['tenant_id'] != tenant_id:
                    raise GatewayDeviceNotFound(device_id=device['id'])
            gw_db.devices.extend([NetworkGatewayDeviceReference(**device)
                                  for device in gw_data['devices']])
            context.session.add(gw_db)
        LOG.debug(_("Created network gateway with id:%s"), gw_db['id'])
        return self._make_network_gateway_dict(gw_db)

    def update_network_gateway(self, context, id, network_gateway):
        gw_data = network_gateway[self.gateway_resource]
        with context.session.begin(subtransactions=True):
            gw_db = self._get_network_gateway(context, id)
            if gw_db.default:
                raise NetworkGatewayUnchangeable(gateway_id=id)
            # Ensure there is something to update before doing it
            if any([gw_db[k] != gw_data[k] for k in gw_data]):
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

    def get_network_gateways(self, context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
        marker_obj = self._get_marker_obj(
            context, 'network_gateway', limit, marker)
        return self._get_collection(context, NetworkGateway,
                                    self._make_network_gateway_dict,
                                    filters=filters, fields=fields,
                                    sorts=sorts, limit=limit,
                                    marker_obj=marker_obj,
                                    page_reverse=page_reverse)

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
            # TODO(salvatore-orlando): Creating a port will give it an IP,
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
            # now deallocate and recycle ip from the port
            for fixed_ip in port.get('fixed_ips', []):
                self._delete_ip_allocation(context, network_id,
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
            # FIXME(salvatore-orlando): Ensure state of port in NSX is
            # consistent with outcome of transaction
            self.delete_port(context, net_connection['port_id'],
                             nw_gw_port_check=False)
            # Remove NetworkConnection record
            context.session.delete(net_connection)

    def _make_gateway_device_dict(self, gateway_device, fields=None,
                                  include_nsx_id=False):
        res = {'id': gateway_device['id'],
               'name': gateway_device['name'],
               'status': gateway_device['status'],
               'connector_type': gateway_device['connector_type'],
               'connector_ip': gateway_device['connector_ip'],
               'tenant_id': gateway_device['tenant_id']}
        if include_nsx_id:
            # Return the NSX mapping as well. This attribute will not be
            # returned in the API response anyway. Ensure it will not be
            # filtered out in field selection.
            if fields:
                fields.append('nsx_id')
            res['nsx_id'] = gateway_device['nsx_id']
        return self._fields(res, fields)

    def _get_gateway_device(self, context, device_id):
        try:
            return self._get_by_id(context, NetworkGatewayDevice, device_id)
        except sa_orm_exc.NoResultFound:
            raise GatewayDeviceNotFound(device_id=device_id)

    def _is_device_in_use(self, context, device_id):
        query = self._get_collection_query(
            context, NetworkGatewayDeviceReference, {'id': [device_id]})
        return query.first()

    def get_gateway_device(self, context, device_id, fields=None,
                           include_nsx_id=False):
        return self._make_gateway_device_dict(
            self._get_gateway_device(context, device_id),
            fields, include_nsx_id)

    def _query_gateway_devices(self, context,
                               filters=None, sorts=None,
                               limit=None, marker=None,
                               page_reverse=None):
        marker_obj = self._get_marker_obj(
            context, 'gateway_device', limit, marker)
        return self._get_collection_query(context,
                                          NetworkGatewayDevice,
                                          filters=filters,
                                          sorts=sorts,
                                          limit=limit,
                                          marker_obj=marker_obj,
                                          page_reverse=page_reverse)

    def get_gateway_devices(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False, include_nsx_id=False):
        query = self._query_gateway_devices(context, filters, sorts, limit,
                                            marker, page_reverse)
        return [self._make_gateway_device_dict(row, fields, include_nsx_id)
                for row in query]

    def create_gateway_device(self, context, gateway_device,
                              initial_status=STATUS_UNKNOWN):
        device_data = gateway_device[self.device_resource]
        tenant_id = self._get_tenant_id_for_create(context, device_data)
        with context.session.begin(subtransactions=True):
            device_db = NetworkGatewayDevice(
                id=device_data.get('id', uuidutils.generate_uuid()),
                tenant_id=tenant_id,
                name=device_data.get('name'),
                connector_type=device_data['connector_type'],
                connector_ip=device_data['connector_ip'],
                status=initial_status)
            context.session.add(device_db)
        LOG.debug(_("Created network gateway device: %s"), device_db['id'])
        return self._make_gateway_device_dict(device_db)

    def update_gateway_device(self, context, gateway_device_id,
                              gateway_device, include_nsx_id=False):
        device_data = gateway_device[self.device_resource]
        with context.session.begin(subtransactions=True):
            device_db = self._get_gateway_device(context, gateway_device_id)
            # Ensure there is something to update before doing it
            if any([device_db[k] != device_data[k] for k in device_data]):
                device_db.update(device_data)
        LOG.debug(_("Updated network gateway device: %s"),
                  gateway_device_id)
        return self._make_gateway_device_dict(
            device_db, include_nsx_id=include_nsx_id)

    def delete_gateway_device(self, context, device_id):
        with context.session.begin(subtransactions=True):
            # A gateway device should not be deleted
            # if it is used in any network gateway service
            if self._is_device_in_use(context, device_id):
                raise GatewayDeviceInUse(device_id=device_id)
            device_db = self._get_gateway_device(context, device_id)
            context.session.delete(device_db)
        LOG.debug(_("Deleted network gateway device: %s."), device_id)
