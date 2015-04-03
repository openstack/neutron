# Copyright 2014 IBM Corp.
#
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


import functools

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging
from oslo_utils import excutils

from neutron.common import constants as n_const
from neutron.common import exceptions as n_exc
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.db import agents_db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import l3_gwmode_db
from neutron.db import portbindings_db
from neutron.db import quota_db  # noqa
from neutron.extensions import portbindings
from neutron.i18n import _LE, _LI, _LW
from neutron.plugins.ibm.common import config  # noqa
from neutron.plugins.ibm.common import constants
from neutron.plugins.ibm.common import exceptions as sdnve_exc
from neutron.plugins.ibm import sdnve_api as sdnve
from neutron.plugins.ibm import sdnve_api_fake as sdnve_fake

LOG = logging.getLogger(__name__)


class SdnveRpcCallbacks(object):

    def __init__(self, notifier):
        self.notifier = notifier  # used to notify the agent

    def sdnve_info(self, rpc_context, **kwargs):
        '''Update new information.'''
        info = kwargs.get('info')
        # Notify all other listening agents
        self.notifier.info_update(rpc_context, info)
        return info


class AgentNotifierApi(object):
    '''Agent side of the SDN-VE rpc API.'''

    def __init__(self, topic):
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)
        self.topic_info_update = topics.get_topic_name(topic,
                                                       constants.INFO,
                                                       topics.UPDATE)

    def info_update(self, context, info):
        cctxt = self.client.prepare(topic=self.topic_info_update, fanout=True)
        cctxt.cast(context, 'info_update', info=info)


def _ha(func):
    '''Supports the high availability feature of the controller.'''

    @functools.wraps(func)
    def hawrapper(self, *args, **kwargs):
        '''This wrapper sets the new controller if necessary

        When a controller is detected to be not responding, and a
        new controller is chosen to be used in its place, this decorator
        makes sure the existing integration bridges are set to point
        to the new controller by calling the set_controller method.
        '''
        ret_func = func(self, *args, **kwargs)
        self.set_controller(args[0])
        return ret_func
    return hawrapper


class SdnvePluginV2(db_base_plugin_v2.NeutronDbPluginV2,
                    external_net_db.External_net_db_mixin,
                    portbindings_db.PortBindingMixin,
                    l3_gwmode_db.L3_NAT_db_mixin,
                    agents_db.AgentDbMixin,
                    ):

    '''
    Implement the Neutron abstractions using SDN-VE SDN Controller.
    '''

    __native_bulk_support = False
    __native_pagination_support = False
    __native_sorting_support = False

    supported_extension_aliases = ["binding", "router", "external-net",
                                   "agent", "quotas"]

    def __init__(self, configfile=None):
        self.base_binding_dict = {
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_OVS,
            portbindings.VIF_DETAILS: {portbindings.CAP_PORT_FILTER: False}}

        super(SdnvePluginV2, self).__init__()
        self.setup_rpc()
        self.sdnve_controller_select()
        if self.fake_controller:
            self.sdnve_client = sdnve_fake.FakeClient()
        else:
            self.sdnve_client = sdnve.Client()

    def sdnve_controller_select(self):
        self.fake_controller = cfg.CONF.SDNVE.use_fake_controller

    def setup_rpc(self):
        # RPC support
        self.topic = topics.PLUGIN
        self.conn = n_rpc.create_connection(new=True)
        self.notifier = AgentNotifierApi(topics.AGENT)
        self.endpoints = [SdnveRpcCallbacks(self.notifier),
                          agents_db.AgentExtRpcCallback()]
        self.conn.create_consumer(self.topic, self.endpoints,
                                  fanout=False)
        # Consume from all consumers in threads
        self.conn.consume_in_threads()

    def _update_base_binding_dict(self, tenant_type):
        if tenant_type == constants.TENANT_TYPE_OVERLAY:
            self.base_binding_dict[
                portbindings.VIF_TYPE] = portbindings.VIF_TYPE_BRIDGE
        if tenant_type == constants.TENANT_TYPE_OF:
            self.base_binding_dict[
                portbindings.VIF_TYPE] = portbindings.VIF_TYPE_OVS

    def set_controller(self, context):
        LOG.info(_LI("Set a new controller if needed."))
        new_controller = self.sdnve_client.sdnve_get_controller()
        if new_controller:
            self.notifier.info_update(
                context,
                {'new_controller': new_controller})
            LOG.info(_LI("Set the controller to a new controller: %s"),
                     new_controller)

    def _process_request(self, request, current):
        new_request = dict(
            (k, v) for k, v in request.items()
            if v != current.get(k))

        msg = _("Original SDN-VE HTTP request: %(orig)s; New request: %(new)s")
        LOG.debug(msg, {'orig': request, 'new': new_request})
        return new_request

    #
    # Network
    #

    @_ha
    def create_network(self, context, network):
        LOG.debug("Create network in progress: %r", network)
        session = context.session

        tenant_id = self._get_tenant_id_for_create(context, network['network'])
        # Create a new SDN-VE tenant if need be
        sdnve_tenant = self.sdnve_client.sdnve_check_and_create_tenant(
            tenant_id)
        if sdnve_tenant is None:
            raise sdnve_exc.SdnveException(
                msg=_('Create net failed: no SDN-VE tenant.'))

        with session.begin(subtransactions=True):
            net = super(SdnvePluginV2, self).create_network(context, network)
            self._process_l3_create(context, net, network['network'])

        # Create SDN-VE network
        (res, data) = self.sdnve_client.sdnve_create('network', net)
        if res not in constants.HTTP_ACCEPTABLE:
            super(SdnvePluginV2, self).delete_network(context, net['id'])
            raise sdnve_exc.SdnveException(
                msg=(_('Create net failed in SDN-VE: %s') % res))

        LOG.debug("Created network: %s", net['id'])
        return net

    @_ha
    def update_network(self, context, id, network):
        LOG.debug("Update network in progress: %r", network)
        session = context.session

        processed_request = {}
        with session.begin(subtransactions=True):
            original_network = super(SdnvePluginV2, self).get_network(
                context, id)
            processed_request['network'] = self._process_request(
                network['network'], original_network)
            net = super(SdnvePluginV2, self).update_network(
                context, id, network)
            self._process_l3_update(context, net, network['network'])

        if processed_request['network']:
            (res, data) = self.sdnve_client.sdnve_update(
                'network', id, processed_request['network'])
            if res not in constants.HTTP_ACCEPTABLE:
                net = super(SdnvePluginV2, self).update_network(
                    context, id, {'network': original_network})
                raise sdnve_exc.SdnveException(
                    msg=(_('Update net failed in SDN-VE: %s') % res))

        return net

    @_ha
    def delete_network(self, context, id):
        LOG.debug("Delete network in progress: %s", id)
        session = context.session

        with session.begin(subtransactions=True):
            self._process_l3_delete(context, id)
            super(SdnvePluginV2, self).delete_network(context, id)

        (res, data) = self.sdnve_client.sdnve_delete('network', id)
        if res not in constants.HTTP_ACCEPTABLE:
            LOG.error(
                _LE("Delete net failed after deleting the network in DB: %s"),
                res)

    @_ha
    def get_network(self, context, id, fields=None):
        LOG.debug("Get network in progress: %s", id)
        return super(SdnvePluginV2, self).get_network(context, id, fields)

    @_ha
    def get_networks(self, context, filters=None, fields=None, sorts=None,
                     limit=None, marker=None, page_reverse=False):
        LOG.debug("Get networks in progress")
        return super(SdnvePluginV2, self).get_networks(
            context, filters, fields, sorts, limit, marker, page_reverse)

    #
    # Port
    #

    @_ha
    def create_port(self, context, port):
        LOG.debug("Create port in progress: %r", port)
        session = context.session

        # Set port status as 'ACTIVE' to avoid needing the agent
        port['port']['status'] = n_const.PORT_STATUS_ACTIVE
        port_data = port['port']

        with session.begin(subtransactions=True):
            port = super(SdnvePluginV2, self).create_port(context, port)
            if 'id' not in port:
                return port
            # If the tenant_id is set to '' by create_port, add the id to
            # the request being sent to the controller as the controller
            # requires a tenant id
            tenant_id = port.get('tenant_id')
            if not tenant_id:
                LOG.debug("Create port does not have tenant id info")
                original_network = super(SdnvePluginV2, self).get_network(
                    context, port['network_id'])
                original_tenant_id = original_network['tenant_id']
                port['tenant_id'] = original_tenant_id
                LOG.debug(
                    "Create port does not have tenant id info; "
                    "obtained is: %s",
                    port['tenant_id'])

            os_tenant_id = tenant_id
            id_na, tenant_type = self.sdnve_client.sdnve_get_tenant_byid(
                os_tenant_id)
            self._update_base_binding_dict(tenant_type)
            self._process_portbindings_create_and_update(context,
                                                         port_data, port)

        # NOTE(mb): Remove this block when controller is updated
        # Remove the information that the controller does not accept
        sdnve_port = port.copy()
        sdnve_port.pop('device_id', None)
        sdnve_port.pop('device_owner', None)

        (res, data) = self.sdnve_client.sdnve_create('port', sdnve_port)
        if res not in constants.HTTP_ACCEPTABLE:
            super(SdnvePluginV2, self).delete_port(context, port['id'])
            raise sdnve_exc.SdnveException(
                msg=(_('Create port failed in SDN-VE: %s') % res))

        LOG.debug("Created port: %s", port.get('id', 'id not found'))
        return port

    @_ha
    def update_port(self, context, id, port):
        LOG.debug("Update port in progress: %r", port)
        session = context.session

        processed_request = {}
        with session.begin(subtransactions=True):
            original_port = super(SdnvePluginV2, self).get_port(
                context, id)
            processed_request['port'] = self._process_request(
                port['port'], original_port)
            updated_port = super(SdnvePluginV2, self).update_port(
                context, id, port)

            os_tenant_id = updated_port['tenant_id']
            id_na, tenant_type = self.sdnve_client.sdnve_get_tenant_byid(
                os_tenant_id)
            self._update_base_binding_dict(tenant_type)
            self._process_portbindings_create_and_update(context,
                                                         port['port'],
                                                         updated_port)

        if processed_request['port']:
            (res, data) = self.sdnve_client.sdnve_update(
                'port', id, processed_request['port'])
            if res not in constants.HTTP_ACCEPTABLE:
                updated_port = super(SdnvePluginV2, self).update_port(
                    context, id, {'port': original_port})
                raise sdnve_exc.SdnveException(
                    msg=(_('Update port failed in SDN-VE: %s') % res))

        return updated_port

    @_ha
    def delete_port(self, context, id, l3_port_check=True):
        LOG.debug("Delete port in progress: %s", id)

        # if needed, check to see if this is a port owned by
        # an l3-router.  If so, we should prevent deletion.
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        self.disassociate_floatingips(context, id)

        super(SdnvePluginV2, self).delete_port(context, id)

        (res, data) = self.sdnve_client.sdnve_delete('port', id)
        if res not in constants.HTTP_ACCEPTABLE:
            LOG.error(
                _LE("Delete port operation failed in SDN-VE "
                    "after deleting the port from DB: %s"), res)

    #
    # Subnet
    #

    @_ha
    def create_subnet(self, context, subnet):
        LOG.debug("Create subnet in progress: %r", subnet)
        new_subnet = super(SdnvePluginV2, self).create_subnet(context, subnet)

        # Note(mb): Use of null string currently required by controller
        sdnve_subnet = new_subnet.copy()
        if subnet.get('gateway_ip') is None:
            sdnve_subnet['gateway_ip'] = 'null'
        (res, data) = self.sdnve_client.sdnve_create('subnet', sdnve_subnet)
        if res not in constants.HTTP_ACCEPTABLE:
            super(SdnvePluginV2, self).delete_subnet(context,
                                                     new_subnet['id'])
            raise sdnve_exc.SdnveException(
                msg=(_('Create subnet failed in SDN-VE: %s') % res))

        LOG.debug("Subnet created: %s", new_subnet['id'])

        return new_subnet

    @_ha
    def update_subnet(self, context, id, subnet):
        LOG.debug("Update subnet in progress: %r", subnet)
        session = context.session

        processed_request = {}
        with session.begin(subtransactions=True):
            original_subnet = super(SdnvePluginV2, self).get_subnet(
                context, id)
            processed_request['subnet'] = self._process_request(
                subnet['subnet'], original_subnet)
            updated_subnet = super(SdnvePluginV2, self).update_subnet(
                context, id, subnet)

        if processed_request['subnet']:
            # Note(mb): Use of string containing null required by controller
            if 'gateway_ip' in processed_request['subnet']:
                if processed_request['subnet'].get('gateway_ip') is None:
                    processed_request['subnet']['gateway_ip'] = 'null'
            (res, data) = self.sdnve_client.sdnve_update(
                'subnet', id, processed_request['subnet'])
            if res not in constants.HTTP_ACCEPTABLE:
                for key in subnet['subnet'].keys():
                    subnet['subnet'][key] = original_subnet[key]
                super(SdnvePluginV2, self).update_subnet(
                    context, id, subnet)
                raise sdnve_exc.SdnveException(
                    msg=(_('Update subnet failed in SDN-VE: %s') % res))

        return updated_subnet

    @_ha
    def delete_subnet(self, context, id):
        LOG.debug("Delete subnet in progress: %s", id)
        super(SdnvePluginV2, self).delete_subnet(context, id)

        (res, data) = self.sdnve_client.sdnve_delete('subnet', id)
        if res not in constants.HTTP_ACCEPTABLE:
            LOG.error(_LE("Delete subnet operation failed in SDN-VE after "
                          "deleting the subnet from DB: %s"), res)

    #
    # Router
    #

    @_ha
    def create_router(self, context, router):
        LOG.debug("Create router in progress: %r", router)

        if router['router']['admin_state_up'] is False:
            LOG.warning(_LW('Ignoring admin_state_up=False for router=%r.  '
                            'Overriding with True'), router)
            router['router']['admin_state_up'] = True

        tenant_id = self._get_tenant_id_for_create(context, router['router'])
        # Create a new SDN-VE tenant if need be
        sdnve_tenant = self.sdnve_client.sdnve_check_and_create_tenant(
            tenant_id)
        if sdnve_tenant is None:
            raise sdnve_exc.SdnveException(
                msg=_('Create router failed: no SDN-VE tenant.'))

        new_router = super(SdnvePluginV2, self).create_router(context, router)
        # Create SDN-VE router
        (res, data) = self.sdnve_client.sdnve_create('router', new_router)
        if res not in constants.HTTP_ACCEPTABLE:
            super(SdnvePluginV2, self).delete_router(context, new_router['id'])
            raise sdnve_exc.SdnveException(
                msg=(_('Create router failed in SDN-VE: %s') % res))

        LOG.debug("Router created: %r", new_router)
        return new_router

    @_ha
    def update_router(self, context, id, router):
        LOG.debug("Update router in progress: id=%(id)s "
                  "router=%(router)r",
                  {'id': id, 'router': router})
        session = context.session

        processed_request = {}
        if not router['router'].get('admin_state_up', True):
            raise n_exc.NotImplementedError(_('admin_state_up=False '
                                              'routers are not '
                                              'supported.'))

        with session.begin(subtransactions=True):
            original_router = super(SdnvePluginV2, self).get_router(
                context, id)
            processed_request['router'] = self._process_request(
                router['router'], original_router)
            updated_router = super(SdnvePluginV2, self).update_router(
                context, id, router)

        if processed_request['router']:
            egw = processed_request['router'].get('external_gateway_info')
            # Check for existing empty set (different from None) in request
            if egw == {}:
                processed_request['router'][
                    'external_gateway_info'] = {'network_id': 'null'}
            (res, data) = self.sdnve_client.sdnve_update(
                'router', id, processed_request['router'])
            if res not in constants.HTTP_ACCEPTABLE:
                super(SdnvePluginV2, self).update_router(
                    context, id, {'router': original_router})
                raise sdnve_exc.SdnveException(
                    msg=(_('Update router failed in SDN-VE: %s') % res))

        return updated_router

    @_ha
    def delete_router(self, context, id):
        LOG.debug("Delete router in progress: %s", id)

        super(SdnvePluginV2, self).delete_router(context, id)

        (res, data) = self.sdnve_client.sdnve_delete('router', id)
        if res not in constants.HTTP_ACCEPTABLE:
            LOG.error(
                _LE("Delete router operation failed in SDN-VE after "
                    "deleting the router in DB: %s"), res)

    @_ha
    def add_router_interface(self, context, router_id, interface_info):
        LOG.debug("Add router interface in progress: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})

        new_interface = super(SdnvePluginV2, self).add_router_interface(
            context, router_id, interface_info)
        LOG.debug(
            "SdnvePluginV2.add_router_interface called. Port info: %s",
            new_interface)
        request_info = interface_info.copy()
        request_info['port_id'] = new_interface['port_id']
        # Add the subnet_id to the request sent to the controller
        if 'subnet_id' not in interface_info:
            request_info['subnet_id'] = new_interface['subnet_id']

        (res, data) = self.sdnve_client.sdnve_update(
            'router', router_id + '/add_router_interface', request_info)
        if res not in constants.HTTP_ACCEPTABLE:
            super(SdnvePluginV2, self).remove_router_interface(
                context, router_id, interface_info)
            raise sdnve_exc.SdnveException(
                msg=(_('Update router-add-interface failed in SDN-VE: %s') %
                     res))

        LOG.debug("Added router interface: %r", new_interface)
        return new_interface

    def _add_router_interface_only(self, context, router_id, interface_info):
        LOG.debug("Add router interface only called: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})

        port_id = interface_info.get('port_id')
        if port_id:
            (res, data) = self.sdnve_client.sdnve_update(
                'router', router_id + '/add_router_interface', interface_info)
            if res not in constants.HTTP_ACCEPTABLE:
                LOG.error(_LE("SdnvePluginV2._add_router_interface_only: "
                              "failed to add the interface in the roll back."
                              " of a remove_router_interface operation"))

    def _find_router_port_by_subnet_id(self, ports, subnet_id):
        for p in ports:
            subnet_ids = [fip['subnet_id'] for fip in p['fixed_ips']]
            if subnet_id in subnet_ids:
                return p['id']

    @_ha
    def remove_router_interface(self, context, router_id, interface_info):
        LOG.debug("Remove router interface in progress: "
                  "router_id=%(router_id)s "
                  "interface_info=%(interface_info)r",
                  {'router_id': router_id, 'interface_info': interface_info})

        subnet_id = interface_info.get('subnet_id')
        port_id = interface_info.get('port_id')
        if not subnet_id:
            if not port_id:
                raise sdnve_exc.BadInputException(msg=_('No port ID'))
            myport = super(SdnvePluginV2, self).get_port(context, port_id)
            LOG.debug("SdnvePluginV2.remove_router_interface port: %s",
                      myport)
            myfixed_ips = myport.get('fixed_ips')
            if not myfixed_ips:
                raise sdnve_exc.BadInputException(msg=_('No fixed IP'))
            subnet_id = myfixed_ips[0].get('subnet_id')
            if subnet_id:
                interface_info['subnet_id'] = subnet_id
                LOG.debug(
                    "SdnvePluginV2.remove_router_interface subnet_id: %s",
                    subnet_id)
        else:
            if not port_id:
                # The backend requires port id info in the request
                subnet = super(SdnvePluginV2, self).get_subnet(context,
                                                               subnet_id)
                df = {'device_id': [router_id],
                      'device_owner': [n_const.DEVICE_OWNER_ROUTER_INTF],
                      'network_id': [subnet['network_id']]}
                ports = self.get_ports(context, filters=df)
                if ports:
                    pid = self._find_router_port_by_subnet_id(ports, subnet_id)
                    if not pid:
                        raise sdnve_exc.SdnveException(
                                msg=(_('Update router-remove-interface '
                                       'failed SDN-VE: subnet %(sid) is not '
                                       'associated with any ports on router '
                                       '%(rid)'), {'sid': subnet_id,
                                     'rid': router_id}))
                    interface_info['port_id'] = pid
                    msg = ("SdnvePluginV2.remove_router_interface "
                           "subnet_id: %(sid)s  port_id: %(pid)s")
                    LOG.debug(msg, {'sid': subnet_id, 'pid': pid})

        (res, data) = self.sdnve_client.sdnve_update(
            'router', router_id + '/remove_router_interface', interface_info)

        if res not in constants.HTTP_ACCEPTABLE:
            raise sdnve_exc.SdnveException(
                msg=(_('Update router-remove-interface failed SDN-VE: %s') %
                     res))

        session = context.session
        with session.begin(subtransactions=True):
            try:
                if not port_id:
                    # port_id was not originally given in interface_info,
                    # so we want to remove the interface by subnet instead
                    # of port
                    del interface_info['port_id']
                info = super(SdnvePluginV2, self).remove_router_interface(
                    context, router_id, interface_info)
            except Exception:
                with excutils.save_and_reraise_exception():
                    self._add_router_interface_only(context,
                                                    router_id, interface_info)

        return info

    #
    # Floating Ip
    #

    @_ha
    def create_floatingip(self, context, floatingip):
        LOG.debug("Create floatingip in progress: %r",
                  floatingip)
        new_floatingip = super(SdnvePluginV2, self).create_floatingip(
            context, floatingip)

        (res, data) = self.sdnve_client.sdnve_create(
            'floatingip', {'floatingip': new_floatingip})
        if res not in constants.HTTP_ACCEPTABLE:
            super(SdnvePluginV2, self).delete_floatingip(
                context, new_floatingip['id'])
            raise sdnve_exc.SdnveException(
                msg=(_('Creating floating ip operation failed '
                       'in SDN-VE controller: %s') % res))

        LOG.debug("Created floatingip : %r", new_floatingip)
        return new_floatingip

    @_ha
    def update_floatingip(self, context, id, floatingip):
        LOG.debug("Update floatingip in progress: %r", floatingip)
        session = context.session

        processed_request = {}
        with session.begin(subtransactions=True):
            original_floatingip = super(
                SdnvePluginV2, self).get_floatingip(context, id)
            processed_request['floatingip'] = self._process_request(
                floatingip['floatingip'], original_floatingip)
            updated_floatingip = super(
                SdnvePluginV2, self).update_floatingip(context, id, floatingip)

        if processed_request['floatingip']:
            (res, data) = self.sdnve_client.sdnve_update(
                'floatingip', id,
                {'floatingip': processed_request['floatingip']})
            if res not in constants.HTTP_ACCEPTABLE:
                super(SdnvePluginV2, self).update_floatingip(
                    context, id, {'floatingip': original_floatingip})
                raise sdnve_exc.SdnveException(
                    msg=(_('Update floating ip failed in SDN-VE: %s') % res))

        return updated_floatingip

    @_ha
    def delete_floatingip(self, context, id):
        LOG.debug("Delete floatingip in progress: %s", id)
        super(SdnvePluginV2, self).delete_floatingip(context, id)

        (res, data) = self.sdnve_client.sdnve_delete('floatingip', id)
        if res not in constants.HTTP_ACCEPTABLE:
            LOG.error(_LE("Delete floatingip failed in SDN-VE: %s"), res)
