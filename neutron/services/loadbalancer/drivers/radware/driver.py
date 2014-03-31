# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Radware LTD.
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
# @author: Avishay Balderman, Radware

import base64
import copy
import httplib
import Queue
import socket
import threading
import time

import eventlet
from oslo.config import cfg

from neutron.common import log as call_log
from neutron import context
from neutron.db.loadbalancer import loadbalancer_db as lb_db
from neutron.extensions import loadbalancer
from neutron.openstack.common import jsonutils as json
from neutron.openstack.common import log as logging
from neutron.plugins.common import constants
from neutron.services.loadbalancer.drivers import abstract_driver
from neutron.services.loadbalancer.drivers.radware import exceptions as r_exc

eventlet.monkey_patch(thread=True)

LOG = logging.getLogger(__name__)

RESP_STATUS = 0
RESP_REASON = 1
RESP_STR = 2
RESP_DATA = 3

TEMPLATE_HEADER = {'Content-Type':
                   'application/vnd.com.radware.vdirect.'
                   'template-parameters+json'}
PROVISION_HEADER = {'Content-Type':
                    'application/vnd.com.radware.'
                    'vdirect.status+json'}
CREATE_SERVICE_HEADER = {'Content-Type':
                         'application/vnd.com.radware.'
                         'vdirect.adc-service-specification+json'}

driver_opts = [
    cfg.StrOpt('vdirect_address',
               help=_('vdirect server IP address')),
    cfg.StrOpt('vdirect_user',
               default='vDirect',
               help=_('vdirect user name')),
    cfg.StrOpt('vdirect_password',
               default='radware',
               help=_('vdirect user password')),
    cfg.StrOpt('service_adc_type',
               default="VA",
               help=_('Service ADC type')),
    cfg.StrOpt('service_adc_version',
               default="",
               help=_('Service ADC version')),
    cfg.BoolOpt('service_ha_pair',
                default=False,
                help=_('service HA pair')),
    cfg.IntOpt('service_throughput',
               default=1000,
               help=_('service throughtput')),
    cfg.IntOpt('service_ssl_throughput',
               default=100,
               help=_('service ssl throughtput')),
    cfg.IntOpt('service_compression_throughput',
               default=100,
               help=_('service compression throughtput')),
    cfg.IntOpt('service_cache',
               default=20,
               help=_('service cache')),
    cfg.StrOpt('l2_l3_workflow_name',
               default='openstack_l2_l3',
               help=_('l2_l3 workflow name')),
    cfg.StrOpt('l4_workflow_name',
               default='openstack_l4',
               help=_('l4 workflow name')),
    cfg.DictOpt('l2_l3_ctor_params',
                default={"service": "_REPLACE_",
                         "ha_network_name": "HA-Network",
                         "ha_ip_pool_name": "default",
                         "allocate_ha_vrrp": True,
                         "allocate_ha_ips": True},
                help=_('l2_l3 workflow constructor params')),
    cfg.DictOpt('l2_l3_setup_params',
                default={"data_port": 1,
                         "data_ip_address": "192.168.200.99",
                         "data_ip_mask": "255.255.255.0",
                         "gateway": "192.168.200.1",
                         "ha_port": 2},
                help=_('l2_l3 workflow setup params')),
    cfg.ListOpt('actions_to_skip',
                default=['setup_l2_l3'],
                help=_('List of actions that we dont want to push to '
                       'the completion queue')),
    cfg.StrOpt('l4_action_name',
               default='BaseCreate',
               help=_('l4 workflow action name')),
    cfg.ListOpt('service_resource_pool_ids',
                default=[],
                help=_('Resource pool ids')),
    cfg.IntOpt('service_isl_vlan',
               default=-1,
               help=_('A required VLAN for the interswitch link to use')),
    cfg.BoolOpt('service_session_mirroring_enabled',
                default=False,
                help=_('Support an Alteon interswitch '
                       'link for stateful session failover'))
]

cfg.CONF.register_opts(driver_opts, "radware")


class LoadBalancerDriver(abstract_driver.LoadBalancerAbstractDriver):

    """Radware lbaas driver."""

    def __init__(self, plugin):
        rad = cfg.CONF.radware
        self.plugin = plugin
        self.service = {
            "haPair": rad.service_ha_pair,
            "sessionMirroringEnabled": rad.service_session_mirroring_enabled,
            "primary": {
                "capacity": {
                    "throughput": rad.service_throughput,
                    "sslThroughput": rad.service_ssl_throughput,
                    "compressionThroughput":
                    rad.service_compression_throughput,
                    "cache": rad.service_cache
                },
                "network": {
                    "type": "portgroup",
                    "portgroups": ['DATA_NETWORK']
                },
                "adcType": rad.service_adc_type,
                "acceptableAdc": "Exact"
            }
        }
        if rad.service_resource_pool_ids:
            ids = rad.service_resource_pool_ids
            self.service['resourcePoolIds'] = [
                {'name': id} for id in ids
            ]
        if rad.service_isl_vlan:
            self.service['islVlan'] = rad.service_isl_vlan
        self.l2_l3_wf_name = rad.l2_l3_workflow_name
        self.l4_wf_name = rad.l4_workflow_name
        self.l2_l3_ctor_params = rad.l2_l3_ctor_params
        self.l2_l3_setup_params = rad.l2_l3_setup_params
        self.l4_action_name = rad.l4_action_name
        self.actions_to_skip = rad.actions_to_skip
        vdirect_address = cfg.CONF.radware.vdirect_address
        self.rest_client = vDirectRESTClient(server=vdirect_address,
                                             user=rad.vdirect_user,
                                             password=rad.vdirect_password)
        self.queue = Queue.Queue()
        self.completion_handler = OperationCompletionHandler(self.queue,
                                                             self.rest_client,
                                                             plugin)
        self.workflow_templates_exists = False
        self.completion_handler.setDaemon(True)
        self.completion_handler_started = False

    def create_vip(self, context, vip):
        LOG.debug(_('create_vip. vip: %s'), str(vip))
        extended_vip = self.plugin.populate_vip_graph(context, vip)
        LOG.debug(_('create_vip. extended_vip: %s'), str(extended_vip))
        network_id = self._get_vip_network_id(context, extended_vip)
        LOG.debug(_('create_vip. network_id: %s '), str(network_id))
        service_name = self._get_service(extended_vip['pool_id'], network_id)
        LOG.debug(_('create_vip. service_name: %s '), service_name)
        self._create_workflow(
            vip['pool_id'], self.l4_wf_name,
            {"service": service_name})
        self._update_workflow(
            vip['pool_id'],
            self.l4_action_name, extended_vip, context)

    def update_vip(self, context, old_vip, vip):
        extended_vip = self.plugin.populate_vip_graph(context, vip)
        self._update_workflow(
            vip['pool_id'], self.l4_action_name,
            extended_vip, context, False, lb_db.Vip, vip['id'])

    def delete_vip(self, context, vip):
        """Delete a Vip

        First delete it from the device. If deletion ended OK
        - remove data from DB as well.
        If the deletion failed - mark vip with error status in DB

        """

        extended_vip = self.plugin.populate_vip_graph(context, vip)
        params = _translate_vip_object_graph(extended_vip,
                                             self.plugin, context)
        ids = params.pop('__ids__')

        try:
            # removing the WF will cause deletion of the configuration from the
            # device
            self._remove_workflow(ids, context)
        except r_exc.RESTRequestFailure:
            pool_id = extended_vip['pool_id']
            LOG.exception(_('Failed to remove workflow %s. '
                            'Going to set vip to ERROR status'),
                          pool_id)

            self.plugin.update_status(context, lb_db.Vip, ids['vip'],
                                      constants.ERROR)

    def create_pool(self, context, pool):
        # nothing to do
        pass

    def update_pool(self, context, old_pool, pool):
        self._handle_pool(context, pool)

    def delete_pool(self, context, pool,):
        self._handle_pool(context, pool, delete=True)

    def _handle_pool(self, context, pool, delete=False):
        vip_id = self.plugin.get_pool(context, pool['id']).get('vip_id', None)
        if vip_id:
            if delete:
                raise loadbalancer.PoolInUse(pool_id=pool['id'])
            else:
                vip = self.plugin.get_vip(context, vip_id)
                extended_vip = self.plugin.populate_vip_graph(context, vip)
                self._update_workflow(
                    pool['id'], self.l4_action_name,
                    extended_vip, context, delete, lb_db.Pool, pool['id'])
        else:
            if delete:
                self.plugin._delete_db_pool(context, pool['id'])
            else:
                # we keep the pool in PENDING_UPDATE
                # no point to modify it since it is not connected to vip yet
                pass

    def create_member(self, context, member):
        self._handle_member(context, member)

    def update_member(self, context, old_member, member):
        self._handle_member(context, member)

    def delete_member(self, context, member):
        self._handle_member(context, member, delete=True)

    def _handle_member(self, context, member, delete=False):
        """Navigate the model. If a Vip is found - activate a bulk WF action.
        """
        vip_id = self.plugin.get_pool(
            context, member['pool_id']).get('vip_id')
        if vip_id:
            vip = self.plugin.get_vip(context, vip_id)
            extended_vip = self.plugin.populate_vip_graph(context, vip)
            self._update_workflow(
                member['pool_id'], self.l4_action_name,
                extended_vip, context,
                delete, lb_db.Member, member['id'])
        # We have to delete this member but it is not connected to a vip yet
        elif delete:
            self.plugin._delete_db_member(context, member['id'])

    def create_health_monitor(self, context, health_monitor):
        # Anything to do here? the hm is not connected to the graph yet
        pass

    def update_pool_health_monitor(self, context, old_health_monitor,
                                   health_monitor,
                                   pool_id):
        self._handle_pool_health_monitor(context, health_monitor, pool_id)

    def create_pool_health_monitor(self, context,
                                   health_monitor, pool_id):
        self._handle_pool_health_monitor(context, health_monitor, pool_id)

    def delete_pool_health_monitor(self, context, health_monitor, pool_id):
        self._handle_pool_health_monitor(context, health_monitor, pool_id,
                                         True)

    def _handle_pool_health_monitor(self, context, health_monitor,
                                    pool_id, delete=False):
        """Push a graph to vDirect

        Navigate the model. Check if a pool is associated to the vip
        and push the graph to vDirect

        """

        vip_id = self.plugin.get_pool(context, pool_id).get('vip_id', None)

        debug_params = {"hm_id": health_monitor['id'], "pool_id": pool_id,
                        "delete": delete, "vip_id": vip_id}
        LOG.debug(_('_handle_pool_health_monitor. health_monitor = %(hm_id)s '
                    'pool_id = %(pool_id)s delete = %(delete)s '
                    'vip_id = %(vip_id)s'),
                  debug_params)

        if vip_id:
            vip = self.plugin.get_vip(context, vip_id)
            extended_vip = self.plugin.populate_vip_graph(context, vip)
            self._update_workflow(pool_id, self.l4_action_name,
                                  extended_vip, context,
                                  delete, lb_db.PoolMonitorAssociation,
                                  health_monitor['id'])
        elif delete:
            self.plugin._delete_db_pool_health_monitor(context,
                                                       health_monitor['id'],
                                                       pool_id)

    def stats(self, context, pool_id):
        # TODO(avishayb) implement
        return {"bytes_in": 0,
                "bytes_out": 0,
                "active_connections": 0,
                "total_connections": 0}

    def _get_vip_network_id(self, context, extended_vip):
        subnet = self.plugin._core_plugin.get_subnet(
            context, extended_vip['subnet_id'])
        return subnet['network_id']

    def _start_completion_handling_thread(self):
        if not self.completion_handler_started:
            LOG.info(_('Starting operation completion handling thread'))
            self.completion_handler.start()
            self.completion_handler_started = True

    @call_log.log
    def _update_workflow(self, wf_name, action,
                         wf_params, context,
                         delete=False,
                         lbaas_entity=None, entity_id=None):
        """Update the WF state. Push the result to a queue for processing."""

        if not self.workflow_templates_exists:
            self._verify_workflow_templates()

        if action not in self.actions_to_skip:
            params = _translate_vip_object_graph(wf_params,
                                                 self.plugin,
                                                 context)
        else:
            params = wf_params

        resource = '/api/workflow/%s/action/%s' % (wf_name, action)
        response = _rest_wrapper(self.rest_client.call('POST', resource,
                                 {'parameters': params},
                                 TEMPLATE_HEADER))
        LOG.debug(_('_update_workflow response: %s '), response)

        if action not in self.actions_to_skip:
            ids = params.pop('__ids__', None)
            oper = OperationAttributes(response['uri'],
                                       ids,
                                       lbaas_entity,
                                       entity_id,
                                       delete=delete)
            LOG.debug(_('Pushing operation %s to the queue'), oper)

            self._start_completion_handling_thread()
            self.queue.put_nowait(oper)

    def _remove_workflow(self, ids, context):

        wf_name = ids['pool']
        LOG.debug(_('Remove the workflow %s') % wf_name)
        resource = '/api/workflow/%s' % (wf_name)
        response = _rest_wrapper(self.rest_client.call('DELETE', resource,
                                 None, None),
                                 [204, 202, 404])
        msg = response.get('message', None)
        if msg == "Not Found":
            self.plugin._delete_db_vip(context, ids['vip'])
        else:
            oper = OperationAttributes(response['uri'],
                                       ids,
                                       lb_db.Vip,
                                       ids['vip'],
                                       delete=True)
            LOG.debug(_('Pushing operation %s to the queue'), oper)

            self._start_completion_handling_thread()
            self.queue.put_nowait(oper)

    def _remove_service(self, service_name):
        resource = '/api/service/%s' % (service_name)
        _rest_wrapper(self.rest_client.call('DELETE',
                      resource, None, None),
                      [202])

    def _get_service(self, pool_id, network_id):
        """Get a service name.

        if you can't find one,
        create a service and create l2_l2 WF.

        """
        if not self.workflow_templates_exists:
            self._verify_workflow_templates()
        incoming_service_name = 'srv_' + network_id
        service_name = self._get_available_service(incoming_service_name)
        if not service_name:
            LOG.debug(
                'Could not find a service named ' + incoming_service_name)
            service_name = self._create_service(pool_id, network_id)
            self.l2_l3_ctor_params["service"] = incoming_service_name
            wf_name = 'l2_l3_' + network_id
            self._create_workflow(
                wf_name, self.l2_l3_wf_name, self.l2_l3_ctor_params)
            self._update_workflow(
                wf_name, "setup_l2_l3", self.l2_l3_setup_params, None)
        else:
            LOG.debug('A service named ' + service_name + ' was found.')
        return service_name

    def _create_service(self, pool_id, network_id):
        """create the service and provision it (async)."""
        # 1) create the service
        service_name = 'srv_' + network_id
        resource = '/api/service?name=%s' % service_name

        service = copy.deepcopy(self.service)
        service['primary']['network']['portgroups'] = [network_id]

        response = _rest_wrapper(self.rest_client.call('POST', resource,
                                 service,
                                 CREATE_SERVICE_HEADER), [201])

        # 2) provision the service
        provision_uri = response['links']['actions']['provision']
        _rest_wrapper(self.rest_client.call('POST', provision_uri,
                                            None, PROVISION_HEADER))
        return service_name

    def _get_available_service(self, service_name):
        """Check if service exsists and return its name if it does."""
        resource = '/api/service/' + service_name
        try:
            _rest_wrapper(self.rest_client.call('GET',
                                                resource,
                                                None, None), [200])
        except Exception:
            return
        return service_name

    def _workflow_exists(self, pool_id):
        """Check if a WF having the name of the pool_id exists."""
        resource = '/api/workflow/' + pool_id
        try:
            _rest_wrapper(self.rest_client.call('GET',
                                                resource,
                                                None,
                                                None), [200])
        except Exception:
            return False
        return True

    def _create_workflow(self, wf_name, wf_template_name,
                         create_workflow_params=None):
        """Create a WF if it doesn't exists yet."""
        if not self.workflow_templates_exists:
                self._verify_workflow_templates()
        if not self._workflow_exists(wf_name):
            if not create_workflow_params:
                create_workflow_params = {}
            resource = '/api/workflowTemplate/%s?name=%s' % (
                wf_template_name, wf_name)
            params = {'parameters': create_workflow_params}
            response = _rest_wrapper(self.rest_client.call('POST',
                                                           resource,
                                                           params,
                                                           TEMPLATE_HEADER))
            LOG.debug(_('create_workflow response: %s'), str(response))

    def _verify_workflow_templates(self):
        """Verify the existence of workflows on vDirect server."""
        workflows = {self.l2_l3_wf_name:
                     False, self.l4_wf_name: False}
        resource = '/api/workflowTemplate'
        response = _rest_wrapper(self.rest_client.call('GET',
                                                       resource,
                                                       None,
                                                       None), [200])
        for wf in workflows.keys():
            for wf_template in response:
                if wf == wf_template['name']:
                    workflows[wf] = True
                    break
        for wf, found in workflows.items():
            if not found:
                raise r_exc.WorkflowMissing(workflow=wf)
        self.workflow_templates_exists = True


class vDirectRESTClient:
    """REST server proxy to Radware vDirect."""

    def __init__(self,
                 server='localhost',
                 user=None,
                 password=None,
                 port=2189,
                 ssl=True,
                 timeout=5000,
                 base_uri=''):
        self.server = server
        self.port = port
        self.ssl = ssl
        self.base_uri = base_uri
        self.timeout = timeout
        if user and password:
            self.auth = base64.encodestring('%s:%s' % (user, password))
            self.auth = self.auth.replace('\n', '')
        else:
            raise r_exc.AuthenticationMissing()

        debug_params = {'server': self.server,
                        'port': self.port,
                        'ssl': self.ssl}
        LOG.debug(_('vDirectRESTClient:init server=%(server)s, '
                  'port=%(port)d, '
                  'ssl=%(ssl)r'), debug_params)

    @call_log.log
    def call(self, action, resource, data, headers, binary=False):
        if resource.startswith('http'):
            uri = resource
        else:
            uri = self.base_uri + resource
        if binary:
            body = data
        else:
            body = json.dumps(data)

        debug_data = 'binary' if binary else body
        debug_data = debug_data if debug_data else 'EMPTY'
        if not headers:
            headers = {'Authorization': 'Basic %s' % self.auth}
        else:
            headers['Authorization'] = 'Basic %s' % self.auth
        conn = None
        if self.ssl:
            conn = httplib.HTTPSConnection(
                self.server, self.port, timeout=self.timeout)
            if conn is None:
                LOG.error(_('vdirectRESTClient: Could not establish HTTPS '
                          'connection'))
                return 0, None, None, None
        else:
            conn = httplib.HTTPConnection(
                self.server, self.port, timeout=self.timeout)
            if conn is None:
                LOG.error(_('vdirectRESTClient: Could not establish HTTP '
                          'connection'))
                return 0, None, None, None

        try:
            conn.request(action, uri, body, headers)
            response = conn.getresponse()
            respstr = response.read()
            respdata = respstr
            try:
                respdata = json.loads(respstr)
            except ValueError:
                # response was not JSON, ignore the exception
                pass
            ret = (response.status, response.reason, respstr, respdata)
        except (socket.timeout, socket.error) as e:
            log_dict = {'action': action, 'e': e}
            LOG.error(_('vdirectRESTClient: %(action)s failure, %(e)r'),
                      log_dict)
            ret = 0, None, None, None
        conn.close()
        return ret


class OperationAttributes:

    """Holds operation attributes."""

    def __init__(self,
                 operation_url,
                 object_graph,
                 lbaas_entity=None,
                 entity_id=None,
                 delete=False):
        self.operation_url = operation_url
        self.object_graph = object_graph
        self.delete = delete
        self.lbaas_entity = lbaas_entity
        self.entity_id = entity_id
        self.creation_time = time.time()

    def __repr__(self):
        items = ("%s = %r" % (k, v) for k, v in self.__dict__.items())
        return "<%s: {%s}>" % (self.__class__.__name__, ', '.join(items))


class OperationCompletionHandler(threading.Thread):

    """Update DB with operation status or delete the entity from DB."""

    def __init__(self, queue, rest_client, plugin):
        threading.Thread.__init__(self)
        self.queue = queue
        self.rest_client = rest_client
        self.plugin = plugin
        self.stoprequest = threading.Event()
        self.opers_to_handle_before_rest = 0

    def join(self, timeout=None):
        self.stoprequest.set()
        super(OperationCompletionHandler, self).join(timeout)

    def handle_operation_completion(self, oper):
        result = self.rest_client.call('GET',
                                       oper.operation_url,
                                       None,
                                       None)
        completed = result[RESP_DATA]['complete']
        reason = result[RESP_REASON],
        description = result[RESP_STR]
        if completed:
            # operation is done - update the DB with the status
            # or delete the entire graph from DB
            success = result[RESP_DATA]['success']
            sec_to_completion = time.time() - oper.creation_time
            debug_data = {'oper': oper,
                          'sec_to_completion': sec_to_completion,
                          'success': success}
            LOG.debug(_('Operation %(oper)s is completed after '
                      '%(sec_to_completion)d sec '
                      'with success status: %(success)s :'),
                      debug_data)
            db_status = None
            if not success:
                # failure - log it and set the return ERROR as DB state
                if reason or description:
                    msg = 'Reason:%s. Description:%s' % (reason, description)
                else:
                    msg = "unknown"
                error_params = {"operation": oper, "msg": msg}
                LOG.error(_('Operation %(operation)s failed. Reason: %(msg)s'),
                          error_params)
                db_status = constants.ERROR
            else:
                if oper.delete:
                    _remove_object_from_db(self.plugin, oper)
                else:
                    db_status = constants.ACTIVE

            if db_status:
                _update_vip_graph_status(self.plugin, oper, db_status)

        return completed

    def run(self):
        oper = None
        while not self.stoprequest.isSet():
            try:
                oper = self.queue.get(timeout=1)

                # Get the current queue size (N) and set the counter with it.
                # Handle N operations with no intermission.
                # Once N operations handles, get the size again and repeat.
                if self.opers_to_handle_before_rest <= 0:
                    self.opers_to_handle_before_rest = self.queue.qsize() + 1

                LOG.debug('Operation consumed from the queue: ' +
                          str(oper))
                # check the status - if oper is done: update the db ,
                # else push the oper again to the queue
                if not self.handle_operation_completion(oper):
                    LOG.debug(_('Operation %s is not completed yet..') % oper)
                    # Not completed - push to the queue again
                    self.queue.put_nowait(oper)

                self.queue.task_done()
                self.opers_to_handle_before_rest -= 1

                # Take one second rest before start handling
                # new operations or operations handled before
                if self.opers_to_handle_before_rest <= 0:
                    time.sleep(1)

            except Queue.Empty:
                continue
            except Exception:
                m = _("Exception was thrown inside OperationCompletionHandler")
                LOG.exception(m)


def _rest_wrapper(response, success_codes=[202]):
    """Wrap a REST call and make sure a valid status is returned."""
    if response[RESP_STATUS] not in success_codes:
        raise r_exc.RESTRequestFailure(
            status=response[RESP_STATUS],
            reason=response[RESP_REASON],
            description=response[RESP_STR],
            success_codes=success_codes
        )
    else:
        return response[RESP_DATA]


def _update_vip_graph_status(plugin, oper, status):
    """Update the status

    Of all the Vip object graph
    or a specific entity in the graph.

    """

    ctx = context.get_admin_context(load_admin_roles=False)

    LOG.debug(_('_update: %s '), oper)
    if oper.lbaas_entity == lb_db.PoolMonitorAssociation:
        plugin.update_pool_health_monitor(ctx,
                                          oper.entity_id,
                                          oper.object_graph['pool'],
                                          status)
    elif oper.entity_id:
        plugin.update_status(ctx,
                             oper.lbaas_entity,
                             oper.entity_id,
                             status)
    else:
        _update_vip_graph_status_cascade(plugin,
                                         oper.object_graph,
                                         ctx, status)


def _update_vip_graph_status_cascade(plugin, ids, ctx, status):
    plugin.update_status(ctx,
                         lb_db.Vip,
                         ids['vip'],
                         status)
    plugin.update_status(ctx,
                         lb_db.Pool,
                         ids['pool'],
                         status)
    for member_id in ids['members']:
        plugin.update_status(ctx,
                             lb_db.Member,
                             member_id,
                             status)
    for hm_id in ids['health_monitors']:
        plugin.update_pool_health_monitor(ctx,
                                          hm_id,
                                          ids['pool'],
                                          status)


def _remove_object_from_db(plugin, oper):
    """Remove a specific entity from db."""
    LOG.debug(_('_remove_object_from_db %s'), str(oper))

    ctx = context.get_admin_context(load_admin_roles=False)

    if oper.lbaas_entity == lb_db.PoolMonitorAssociation:
        plugin._delete_db_pool_health_monitor(ctx,
                                              oper.entity_id,
                                              oper.object_graph['pool'])
    elif oper.lbaas_entity == lb_db.Member:
        plugin._delete_db_member(ctx, oper.entity_id)
    elif oper.lbaas_entity == lb_db.Vip:
        plugin._delete_db_vip(ctx, oper.entity_id)
    elif oper.lbaas_entity == lb_db.Pool:
        plugin._delete_db_pool(ctx, oper.entity_id)
    else:
        raise r_exc.UnsupportedEntityOperation(
            operation='Remove from DB', entity=oper.lbaas_entity
        )

TRANSLATION_DEFAULTS = {'session_persistence_type': 'SOURCE_IP',
                        'session_persistence_cookie_name': 'none',
                        'url_path': '/',
                        'http_method': 'GET',
                        'expected_codes': '200'
                        }
VIP_PROPERTIES = ['address', 'protocol_port', 'protocol', 'connection_limit',
                  'admin_state_up', 'session_persistence_type',
                  'session_persistence_cookie_name']
POOL_PROPERTIES = ['protocol', 'lb_method', 'admin_state_up']
MEMBER_PROPERTIES = ['address', 'protocol_port', 'weight', 'admin_state_up']
HEALTH_MONITOR_PROPERTIES = ['type', 'delay', 'timeout', 'max_retries',
                             'admin_state_up', 'url_path', 'http_method',
                             'expected_codes', 'id']


def _translate_vip_object_graph(extended_vip, plugin, context):
    """Translate the extended vip

    translate to a structure that can be
    understood by the workflow.

    """
    def _create_key(prefix, property_name):
        return prefix + '_' + property_name + '_array'

    def _trans_prop_name(prop_name):
        if prop_name == 'id':
            return 'uuid'
        else:
            return prop_name

    def get_ids(extended_vip):
        ids = {}
        ids['vip'] = extended_vip['id']
        ids['pool'] = extended_vip['pool']['id']
        ids['members'] = [m['id'] for m in extended_vip['members']]
        ids['health_monitors'] = [
            hm['id'] for hm in extended_vip['health_monitors']
        ]
        return ids

    trans_vip = {}
    LOG.debug('Vip graph to be translated: ' + str(extended_vip))
    for vip_property in VIP_PROPERTIES:
        trans_vip['vip_' + vip_property] = extended_vip.get(
            vip_property, TRANSLATION_DEFAULTS.get(vip_property))
    for pool_property in POOL_PROPERTIES:
        trans_vip['pool_' + pool_property] = extended_vip[
            'pool'][pool_property]
    for member_property in MEMBER_PROPERTIES:
        trans_vip[_create_key('member', member_property)] = []
    for member in extended_vip['members']:
        if member['status'] != constants.PENDING_DELETE:
            for member_property in MEMBER_PROPERTIES:
                trans_vip[_create_key('member', member_property)].append(
                    member.get(member_property,
                               TRANSLATION_DEFAULTS.get(member_property)))
    for hm_property in HEALTH_MONITOR_PROPERTIES:
        trans_vip[
            _create_key('hm', _trans_prop_name(hm_property))] = []
    for hm in extended_vip['health_monitors']:
        hm_pool = plugin.get_pool_health_monitor(context,
                                                 hm['id'],
                                                 extended_vip['pool']['id'])
        if hm_pool['status'] != constants.PENDING_DELETE:
            for hm_property in HEALTH_MONITOR_PROPERTIES:
                value = hm.get(hm_property,
                               TRANSLATION_DEFAULTS.get(hm_property))
                trans_vip[_create_key('hm',
                          _trans_prop_name(hm_property))].append(value)
    ids = get_ids(extended_vip)
    trans_vip['__ids__'] = ids
    LOG.debug('Translated Vip graph: ' + str(trans_vip))
    return trans_vip
