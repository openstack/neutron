# Copyright 2013, Nachi Ueno, NTT I3, Inc.
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
import abc
import copy
import os
import re
import shutil

import jinja2
import netaddr
from oslo.config import cfg
from oslo import messaging
import six

from neutron.agent.linux import ip_lib
from neutron.agent.linux import utils
from neutron.common import rpc as n_rpc
from neutron import context
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging
from neutron.openstack.common import loopingcall
from neutron.plugins.common import constants
from neutron.plugins.common import utils as plugin_utils
from neutron.services.vpn.common import topics
from neutron.services.vpn import device_drivers

LOG = logging.getLogger(__name__)
TEMPLATE_PATH = os.path.dirname(__file__)

ipsec_opts = [
    cfg.StrOpt(
        'config_base_dir',
        default='$state_path/ipsec',
        help=_('Location to store ipsec server config files')),
    cfg.IntOpt('ipsec_status_check_interval',
               default=60,
               help=_("Interval for checking ipsec status"))
]
cfg.CONF.register_opts(ipsec_opts, 'ipsec')

openswan_opts = [
    cfg.StrOpt(
        'ipsec_config_template',
        default=os.path.join(
            TEMPLATE_PATH,
            'template/openswan/ipsec.conf.template'),
        help=_('Template file for ipsec configuration')),
    cfg.StrOpt(
        'ipsec_secret_template',
        default=os.path.join(
            TEMPLATE_PATH,
            'template/openswan/ipsec.secret.template'),
        help=_('Template file for ipsec secret configuration'))
]

cfg.CONF.register_opts(openswan_opts, 'openswan')

JINJA_ENV = None

STATUS_MAP = {
    'erouted': constants.ACTIVE,
    'unrouted': constants.DOWN
}

IPSEC_CONNS = 'ipsec_site_connections'


def _get_template(template_file):
    global JINJA_ENV
    if not JINJA_ENV:
        templateLoader = jinja2.FileSystemLoader(searchpath="/")
        JINJA_ENV = jinja2.Environment(loader=templateLoader)
    return JINJA_ENV.get_template(template_file)


@six.add_metaclass(abc.ABCMeta)
class BaseSwanProcess():
    """Swan Family Process Manager

    This class manages start/restart/stop ipsec process.
    This class create/delete config template
    """

    binary = "ipsec"
    CONFIG_DIRS = [
        'var/run',
        'log',
        'etc',
        'etc/ipsec.d/aacerts',
        'etc/ipsec.d/acerts',
        'etc/ipsec.d/cacerts',
        'etc/ipsec.d/certs',
        'etc/ipsec.d/crls',
        'etc/ipsec.d/ocspcerts',
        'etc/ipsec.d/policies',
        'etc/ipsec.d/private',
        'etc/ipsec.d/reqs',
        'etc/pki/nssdb/'
    ]

    DIALECT_MAP = {
        "3des": "3des",
        "aes-128": "aes128",
        "aes-256": "aes256",
        "aes-192": "aes192",
        "group2": "modp1024",
        "group5": "modp1536",
        "group14": "modp2048",
        "group15": "modp3072",
        "bi-directional": "start",
        "response-only": "add",
        "v2": "insist",
        "v1": "never"
    }

    def __init__(self, conf, root_helper, process_id,
                 vpnservice, namespace):
        self.conf = conf
        self.id = process_id
        self.root_helper = root_helper
        self.updated_pending_status = False
        self.namespace = namespace
        self.connection_status = {}
        self.config_dir = os.path.join(
            cfg.CONF.ipsec.config_base_dir, self.id)
        self.etc_dir = os.path.join(self.config_dir, 'etc')
        self.update_vpnservice(vpnservice)

    def translate_dialect(self):
        if not self.vpnservice:
            return
        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            self._dialect(ipsec_site_conn, 'initiator')
            self._dialect(ipsec_site_conn['ikepolicy'], 'ike_version')
            for key in ['encryption_algorithm',
                        'auth_algorithm',
                        'pfs']:
                self._dialect(ipsec_site_conn['ikepolicy'], key)
                self._dialect(ipsec_site_conn['ipsecpolicy'], key)

    def update_vpnservice(self, vpnservice):
        self.vpnservice = vpnservice
        self.translate_dialect()

    def _dialect(self, obj, key):
        obj[key] = self.DIALECT_MAP.get(obj[key], obj[key])

    @abc.abstractmethod
    def ensure_configs(self):
        pass

    def ensure_config_file(self, kind, template, vpnservice):
        """Update config file,  based on current settings for service."""
        config_str = self._gen_config_content(template, vpnservice)
        config_file_name = self._get_config_filename(kind)
        utils.replace_file(config_file_name, config_str)

    def remove_config(self):
        """Remove whole config file."""
        shutil.rmtree(self.config_dir, ignore_errors=True)

    def _get_config_filename(self, kind):
        config_dir = self.etc_dir
        return os.path.join(config_dir, kind)

    def _ensure_dir(self, dir_path):
        if not os.path.isdir(dir_path):
            os.makedirs(dir_path, 0o755)

    def ensure_config_dir(self, vpnservice):
        """Create config directory if it does not exist."""
        self._ensure_dir(self.config_dir)
        for subdir in self.CONFIG_DIRS:
            dir_path = os.path.join(self.config_dir, subdir)
            self._ensure_dir(dir_path)

    def _gen_config_content(self, template_file, vpnservice):
        template = _get_template(template_file)
        return template.render(
            {'vpnservice': vpnservice,
             'state_path': cfg.CONF.state_path})

    @abc.abstractmethod
    def get_status(self):
        pass

    @property
    def status(self):
        if self.active:
            return constants.ACTIVE
        return constants.DOWN

    @property
    def active(self):
        """Check if the process is active or not."""
        if not self.namespace:
            return False
        try:
            status = self.get_status()
            self._update_connection_status(status)
        except RuntimeError:
            return False
        return True

    def update(self):
        """Update Status based on vpnservice configuration."""
        if self.vpnservice and not self.vpnservice['admin_state_up']:
            self.disable()
        else:
            self.enable()

        if plugin_utils.in_pending_status(self.vpnservice['status']):
            self.updated_pending_status = True

        self.vpnservice['status'] = self.status
        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            if plugin_utils.in_pending_status(ipsec_site_conn['status']):
                conn_id = ipsec_site_conn['id']
                conn_status = self.connection_status.get(conn_id)
                if not conn_status:
                    continue
                conn_status['updated_pending_status'] = True
                ipsec_site_conn['status'] = conn_status['status']

    def enable(self):
        """Enabling the process."""
        try:
            self.ensure_configs()
            if self.active:
                self.restart()
            else:
                self.start()
        except RuntimeError:
            LOG.exception(
                _("Failed to enable vpn process on router %s"),
                self.id)

    def disable(self):
        """Disabling the process."""
        try:
            if self.active:
                self.stop()
            self.remove_config()
        except RuntimeError:
            LOG.exception(
                _("Failed to disable vpn process on router %s"),
                self.id)

    @abc.abstractmethod
    def restart(self):
        """Restart process."""

    @abc.abstractmethod
    def start(self):
        """Start process."""

    @abc.abstractmethod
    def stop(self):
        """Stop process."""

    def _update_connection_status(self, status_output):
        for line in status_output.split('\n'):
            m = re.search('\d\d\d "([a-f0-9\-]+).* (unrouted|erouted);', line)
            if not m:
                continue
            connection_id = m.group(1)
            status = m.group(2)
            if not self.connection_status.get(connection_id):
                self.connection_status[connection_id] = {
                    'status': None,
                    'updated_pending_status': False
                }
            self.connection_status[
                connection_id]['status'] = STATUS_MAP[status]


class OpenSwanProcess(BaseSwanProcess):
    """OpenSwan Process manager class.

    This process class uses three commands
    (1) ipsec pluto:  IPsec IKE keying daemon
    (2) ipsec addconn: Adds new ipsec addconn
    (3) ipsec whack:  control interface for IPSEC keying daemon
    """
    def __init__(self, conf, root_helper, process_id,
                 vpnservice, namespace):
        super(OpenSwanProcess, self).__init__(
            conf, root_helper, process_id,
            vpnservice, namespace)
        self.secrets_file = os.path.join(
            self.etc_dir, 'ipsec.secrets')
        self.config_file = os.path.join(
            self.etc_dir, 'ipsec.conf')
        self.pid_path = os.path.join(
            self.config_dir, 'var', 'run', 'pluto')

    def _execute(self, cmd, check_exit_code=True):
        """Execute command on namespace."""
        ip_wrapper = ip_lib.IPWrapper(self.root_helper, self.namespace)
        return ip_wrapper.netns.execute(
            cmd,
            check_exit_code=check_exit_code)

    def ensure_configs(self):
        """Generate config files which are needed for OpenSwan.

        If there is no directory, this function will create
        dirs.
        """
        self.ensure_config_dir(self.vpnservice)
        self.ensure_config_file(
            'ipsec.conf',
            self.conf.openswan.ipsec_config_template,
            self.vpnservice)
        self.ensure_config_file(
            'ipsec.secrets',
            self.conf.openswan.ipsec_secret_template,
            self.vpnservice)

    def get_status(self):
        return self._execute([self.binary,
                              'whack',
                              '--ctlbase',
                              self.pid_path,
                              '--status'])

    def restart(self):
        """Restart the process."""
        self.stop()
        self.start()
        return

    def _get_nexthop(self, address):
        routes = self._execute(
            ['ip', 'route', 'get', address])
        if routes.find('via') >= 0:
            return routes.split(' ')[2]
        return address

    def _virtual_privates(self):
        """Returns line of virtual_privates.

        virtual_private contains the networks
        that are allowed as subnet for the remote client.
        """
        virtual_privates = []
        nets = [self.vpnservice['subnet']['cidr']]
        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            nets += ipsec_site_conn['peer_cidrs']
        for net in nets:
            version = netaddr.IPNetwork(net).version
            virtual_privates.append('%%v%s:%s' % (version, net))
        return ','.join(virtual_privates)

    def start(self):
        """Start the process.

        Note: if there is not namespace yet,
        just do nothing, and wait next event.
        """
        if not self.namespace:
            return
        virtual_private = self._virtual_privates()
        #start pluto IKE keying daemon
        self._execute([self.binary,
                       'pluto',
                       '--ctlbase', self.pid_path,
                       '--ipsecdir', self.etc_dir,
                       '--use-netkey',
                       '--uniqueids',
                       '--nat_traversal',
                       '--secretsfile', self.secrets_file,
                       '--virtual_private', virtual_private
                       ])
        #add connections
        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            nexthop = self._get_nexthop(ipsec_site_conn['peer_address'])
            self._execute([self.binary,
                           'addconn',
                           '--ctlbase', '%s.ctl' % self.pid_path,
                           '--defaultroutenexthop', nexthop,
                           '--config', self.config_file,
                           ipsec_site_conn['id']
                           ])
        #TODO(nati) fix this when openswan is fixed
        #Due to openswan bug, this command always exit with 3
        #start whack ipsec keying daemon
        self._execute([self.binary,
                       'whack',
                       '--ctlbase', self.pid_path,
                       '--listen',
                       ], check_exit_code=False)

        for ipsec_site_conn in self.vpnservice['ipsec_site_connections']:
            if not ipsec_site_conn['initiator'] == 'start':
                continue
            #initiate ipsec connection
            self._execute([self.binary,
                           'whack',
                           '--ctlbase', self.pid_path,
                           '--name', ipsec_site_conn['id'],
                           '--asynchronous',
                           '--initiate'
                           ])

    def disconnect(self):
        if not self.namespace:
            return
        if not self.vpnservice:
            return
        for conn_id in self.connection_status:
            self._execute([self.binary,
                           'whack',
                           '--ctlbase', self.pid_path,
                           '--name', '%s/0x1' % conn_id,
                           '--terminate'
                           ])

    def stop(self):
        #Stop process using whack
        #Note this will also stop pluto
        self.disconnect()
        self._execute([self.binary,
                       'whack',
                       '--ctlbase', self.pid_path,
                       '--shutdown',
                       ])
        #clean connection_status info
        self.connection_status = {}


class IPsecVpnDriverApi(n_rpc.RpcProxy):
    """IPSecVpnDriver RPC api."""
    IPSEC_PLUGIN_VERSION = '1.0'

    def get_vpn_services_on_host(self, context, host):
        """Get list of vpnservices.

        The vpnservices including related ipsec_site_connection,
        ikepolicy and ipsecpolicy on this host
        """
        return self.call(context,
                         self.make_msg('get_vpn_services_on_host',
                                       host=host),
                         version=self.IPSEC_PLUGIN_VERSION)

    def update_status(self, context, status):
        """Update local status.

        This method call updates status attribute of
        VPNServices.
        """
        return self.cast(context,
                         self.make_msg('update_status',
                                       status=status),
                         version=self.IPSEC_PLUGIN_VERSION)


@six.add_metaclass(abc.ABCMeta)
class IPsecDriver(device_drivers.DeviceDriver):
    """VPN Device Driver for IPSec.

    This class is designed for use with L3-agent now.
    However this driver will be used with another agent in future.
    so the use of "Router" is kept minimul now.
    Instead of router_id,  we are using process_id in this code.
    """

    # history
    #   1.0 Initial version

    RPC_API_VERSION = '1.0'

    # TODO(ihrachys): we can't use RpcCallback here due to inheritance
    # issues
    target = messaging.Target(version=RPC_API_VERSION)

    def __init__(self, agent, host):
        self.agent = agent
        self.conf = self.agent.conf
        self.root_helper = self.agent.root_helper
        self.host = host
        self.conn = n_rpc.create_connection(new=True)
        self.context = context.get_admin_context_without_session()
        self.topic = topics.IPSEC_AGENT_TOPIC
        node_topic = '%s.%s' % (self.topic, self.host)

        self.processes = {}
        self.process_status_cache = {}

        self.endpoints = [self]
        self.conn.create_consumer(node_topic, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        self.agent_rpc = IPsecVpnDriverApi(topics.IPSEC_DRIVER_TOPIC, '1.0')
        self.process_status_cache_check = loopingcall.FixedIntervalLoopingCall(
            self.report_status, self.context)
        self.process_status_cache_check.start(
            interval=self.conf.ipsec.ipsec_status_check_interval)

    def _update_nat(self, vpnservice, func):
        """Setting up nat rule in iptables.

        We need to setup nat rule for ipsec packet.
        :param vpnservice: vpnservices
        :param func: self.add_nat_rule or self.remove_nat_rule
        """
        local_cidr = vpnservice['subnet']['cidr']
        router_id = vpnservice['router_id']
        for ipsec_site_connection in vpnservice['ipsec_site_connections']:
            for peer_cidr in ipsec_site_connection['peer_cidrs']:
                func(
                    router_id,
                    'POSTROUTING',
                    '-s %s -d %s -m policy '
                    '--dir out --pol ipsec '
                    '-j ACCEPT ' % (local_cidr, peer_cidr),
                    top=True)
        self.agent.iptables_apply(router_id)

    def vpnservice_updated(self, context, **kwargs):
        """Vpnservice updated rpc handler

        VPN Service Driver will call this method
        when vpnservices updated.
        Then this method start sync with server.
        """
        self.sync(context, [])

    @abc.abstractmethod
    def create_process(self, process_id, vpnservice, namespace):
        pass

    def ensure_process(self, process_id, vpnservice=None):
        """Ensuring process.

        If the process doesn't exist, it will create process
        and store it in self.processs
        """
        process = self.processes.get(process_id)
        if not process or not process.namespace:
            namespace = self.agent.get_namespace(process_id)
            process = self.create_process(
                process_id,
                vpnservice,
                namespace)
            self.processes[process_id] = process
        elif vpnservice:
            process.update_vpnservice(vpnservice)
        return process

    def create_router(self, process_id):
        """Handling create router event.

        Agent calls this method, when the process namespace
        is ready.
        """
        if process_id in self.processes:
            # In case of vpnservice is created
            # before router's namespace
            process = self.processes[process_id]
            self._update_nat(process.vpnservice, self.agent.add_nat_rule)
            process.enable()

    def destroy_router(self, process_id):
        """Handling destroy_router event.

        Agent calls this method, when the process namespace
        is deleted.
        """
        if process_id in self.processes:
            process = self.processes[process_id]
            process.disable()
            vpnservice = process.vpnservice
            if vpnservice:
                self._update_nat(vpnservice, self.agent.remove_nat_rule)
            del self.processes[process_id]

    def get_process_status_cache(self, process):
        if not self.process_status_cache.get(process.id):
            self.process_status_cache[process.id] = {
                'status': None,
                'id': process.vpnservice['id'],
                'updated_pending_status': False,
                'ipsec_site_connections': {}}
        return self.process_status_cache[process.id]

    def is_status_updated(self, process, previous_status):
        if process.updated_pending_status:
            return True
        if process.status != previous_status['status']:
            return True
        if (process.connection_status !=
            previous_status['ipsec_site_connections']):
            return True

    def unset_updated_pending_status(self, process):
        process.updated_pending_status = False
        for connection_status in process.connection_status.values():
            connection_status['updated_pending_status'] = False

    def copy_process_status(self, process):
        return {
            'id': process.vpnservice['id'],
            'status': process.status,
            'updated_pending_status': process.updated_pending_status,
            'ipsec_site_connections': copy.deepcopy(process.connection_status)
        }

    def update_downed_connections(self, process_id, new_status):
        """Update info to be reported, if connections just went down.

        If there is no longer any information for a connection, because it
        has been removed (e.g. due to an admin down of VPN service or IPSec
        connection), but there was previous status information for the
        connection, mark the connection as down for reporting purposes.
        """
        if process_id in self.process_status_cache:
            for conn in self.process_status_cache[process_id][IPSEC_CONNS]:
                if conn not in new_status[IPSEC_CONNS]:
                    new_status[IPSEC_CONNS][conn] = {
                        'status': constants.DOWN,
                        'updated_pending_status': True
                    }

    def report_status(self, context):
        status_changed_vpn_services = []
        for process in self.processes.values():
            previous_status = self.get_process_status_cache(process)
            if self.is_status_updated(process, previous_status):
                new_status = self.copy_process_status(process)
                self.update_downed_connections(process.id, new_status)
                status_changed_vpn_services.append(new_status)
                self.process_status_cache[process.id] = (
                    self.copy_process_status(process))
                # We need unset updated_pending status after it
                # is reported to the server side
                self.unset_updated_pending_status(process)

        if status_changed_vpn_services:
            self.agent_rpc.update_status(
                context,
                status_changed_vpn_services)

    @lockutils.synchronized('vpn-agent', 'neutron-')
    def sync(self, context, routers):
        """Sync status with server side.

        :param context: context object for RPC call
        :param routers: Router objects which is created in this sync event

        There could be many failure cases should be
        considered including the followings.
        1) Agent class restarted
        2) Failure on process creation
        3) VpnService is deleted during agent down
        4) RPC failure

        In order to handle, these failure cases,
        This driver takes simple sync strategies.
        """
        vpnservices = self.agent_rpc.get_vpn_services_on_host(
            context, self.host)
        router_ids = [vpnservice['router_id'] for vpnservice in vpnservices]
        # Ensure the ipsec process is enabled
        for vpnservice in vpnservices:
            process = self.ensure_process(vpnservice['router_id'],
                                          vpnservice=vpnservice)
            self._update_nat(vpnservice, self.agent.add_nat_rule)
            process.update()

        # Delete any IPSec processes that are
        # associated with routers, but are not running the VPN service.
        for router in routers:
            #We are using router id as process_id
            process_id = router['id']
            if process_id not in router_ids:
                process = self.ensure_process(process_id)
                self.destroy_router(process_id)

        # Delete any IPSec processes running
        # VPN that do not have an associated router.
        process_ids = [process_id
                       for process_id in self.processes
                       if process_id not in router_ids]
        for process_id in process_ids:
            self.destroy_router(process_id)
        self.report_status(context)


class OpenSwanDriver(IPsecDriver):
    def create_process(self, process_id, vpnservice, namespace):
        return OpenSwanProcess(
            self.conf,
            self.root_helper,
            process_id,
            vpnservice,
            namespace)
