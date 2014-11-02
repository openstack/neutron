# Copyright (c) 2013-2014 OpenStack Foundation
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

import time

from oslo.config import cfg
import requests

from neutron.common import constants as n_const
from neutron.common import exceptions as n_exc
from neutron.common import utils
from neutron.extensions import portbindings
from neutron.openstack.common import excutils
from neutron.openstack.common import jsonutils
from neutron.openstack.common import log
from neutron.plugins.common import constants
from neutron.plugins.ml2 import driver_api as api

LOG = log.getLogger(__name__)

ODL_NETWORKS = 'networks'
ODL_SUBNETS = 'subnets'
ODL_PORTS = 'ports'

odl_opts = [
    cfg.StrOpt('url',
               help=_("HTTP URL of OpenDaylight REST interface.")),
    cfg.StrOpt('username',
               help=_("HTTP username for authentication")),
    cfg.StrOpt('password', secret=True,
               help=_("HTTP password for authentication")),
    cfg.IntOpt('timeout', default=10,
               help=_("HTTP timeout in seconds.")),
    cfg.IntOpt('session_timeout', default=30,
               help=_("Tomcat session timeout in minutes.")),
]

cfg.CONF.register_opts(odl_opts, "ml2_odl")


def try_del(d, keys):
    """Ignore key errors when deleting from a dictionary."""
    for key in keys:
        try:
            del d[key]
        except KeyError:
            pass


class OpendaylightAuthError(n_exc.NeutronException):
    message = '%(msg)s'


class JsessionId(requests.auth.AuthBase):

    """Attaches the JSESSIONID and JSESSIONIDSSO cookies to an HTTP Request.

    If the cookies are not available or when the session expires, a new
    set of cookies are obtained.
    """

    def __init__(self, url, username, password):
        """Initialization function for JsessionId."""

        # NOTE(kmestery) The 'limit' paramater is intended to limit how much
        # data is returned from ODL. This is not implemented in the Hydrogen
        # release of OpenDaylight, but will be implemented in the Helium
        # timeframe. Hydrogen will silently ignore this value.
        self.url = str(url) + '/' + ODL_NETWORKS + '?limit=1'
        self.username = username
        self.password = password
        self.auth_cookies = None
        self.last_request = None
        self.expired = None
        self.session_timeout = cfg.CONF.ml2_odl.session_timeout * 60
        self.session_deadline = 0

    def obtain_auth_cookies(self):
        """Make a REST call to obtain cookies for ODL authenticiation."""

        try:
            r = requests.get(self.url, auth=(self.username, self.password))
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            raise OpendaylightAuthError(msg="Failed to authenticate with "
                                        "OpenDaylight: %s" % e)
        except requests.exceptions.Timeout as e:
            raise OpendaylightAuthError(msg="Authentication Timed Out: %s" % e)

        jsessionid = r.cookies.get('JSESSIONID')
        jsessionidsso = r.cookies.get('JSESSIONIDSSO')
        if jsessionid and jsessionidsso:
            self.auth_cookies = dict(JSESSIONID=jsessionid,
                                     JSESSIONIDSSO=jsessionidsso)

    def __call__(self, r):
        """Verify timestamp for Tomcat session timeout."""

        if time.time() > self.session_deadline:
            self.obtain_auth_cookies()
        self.session_deadline = time.time() + self.session_timeout
        r.prepare_cookies(self.auth_cookies)
        return r


class OpenDaylightMechanismDriver(api.MechanismDriver):

    """Mechanism Driver for OpenDaylight.

    This driver was a port from the Tail-F NCS MechanismDriver.  The API
    exposed by ODL is slightly different from the API exposed by NCS,
    but the general concepts are the same.
    """
    auth = None
    out_of_sync = True

    def initialize(self):
        self.url = cfg.CONF.ml2_odl.url
        self.timeout = cfg.CONF.ml2_odl.timeout
        self.username = cfg.CONF.ml2_odl.username
        self.password = cfg.CONF.ml2_odl.password
        required_opts = ('url', 'username', 'password')
        for opt in required_opts:
            if not getattr(self, opt):
                raise cfg.RequiredOptError(opt, 'ml2_odl')
        self.auth = JsessionId(self.url, self.username, self.password)
        self.vif_type = portbindings.VIF_TYPE_OVS
        self.vif_details = {portbindings.CAP_PORT_FILTER: True}

    # Postcommit hooks are used to trigger synchronization.

    def create_network_postcommit(self, context):
        self.synchronize('create', ODL_NETWORKS, context)

    def update_network_postcommit(self, context):
        self.synchronize('update', ODL_NETWORKS, context)

    def delete_network_postcommit(self, context):
        self.synchronize('delete', ODL_NETWORKS, context)

    def create_subnet_postcommit(self, context):
        self.synchronize('create', ODL_SUBNETS, context)

    def update_subnet_postcommit(self, context):
        self.synchronize('update', ODL_SUBNETS, context)

    def delete_subnet_postcommit(self, context):
        self.synchronize('delete', ODL_SUBNETS, context)

    def create_port_postcommit(self, context):
        self.synchronize('create', ODL_PORTS, context)

    def update_port_postcommit(self, context):
        self.synchronize('update', ODL_PORTS, context)

    def delete_port_postcommit(self, context):
        self.synchronize('delete', ODL_PORTS, context)

    def synchronize(self, operation, object_type, context):
        """Synchronize ODL with Neutron following a configuration change."""
        if self.out_of_sync:
            self.sync_full(context)
        else:
            self.sync_single_resource(operation, object_type, context)

    @staticmethod
    def filter_create_network_attributes(network, context):
        """Filter out network attributes not required for a create."""
        try_del(network, ['status', 'subnets'])

    @staticmethod
    def filter_create_subnet_attributes(subnet, context):
        """Filter out subnet attributes not required for a create."""
        pass

    @classmethod
    def filter_create_port_attributes(cls, port, context):
        """Filter out port attributes not required for a create."""
        cls.add_security_groups(port, context)
        # TODO(kmestery): Converting to uppercase due to ODL bug
        # https://bugs.opendaylight.org/show_bug.cgi?id=477
        port['mac_address'] = port['mac_address'].upper()
        try_del(port, ['status'])

    def sync_resources(self, collection_name, context):
        """Sync objects from Neutron over to OpenDaylight.

        This will handle syncing networks, subnets, and ports from Neutron to
        OpenDaylight. It also filters out the requisite items which are not
        valid for create API operations.
        """
        to_be_synced = []
        dbcontext = context._plugin_context
        obj_getter = getattr(context._plugin, 'get_%s' % collection_name)
        resources = obj_getter(dbcontext)
        for resource in resources:
            try:
                urlpath = collection_name + '/' + resource['id']
                self.sendjson('get', urlpath, None)
            except requests.exceptions.HTTPError as e:
                with excutils.save_and_reraise_exception() as ctx:
                    if e.response.status_code == requests.codes.not_found:
                        attr_filter = self.create_object_map[collection_name]
                        attr_filter(resource, context)
                        to_be_synced.append(resource)
                        ctx.reraise = False
        key = collection_name[:-1] if len(to_be_synced) == 1 else (
            collection_name)
        self.sendjson('post', collection_name, {key: to_be_synced})

    @utils.synchronized('odl-sync-full')
    def sync_full(self, context):
        """Resync the entire database to ODL.

        Transition to the in-sync state on success.
        Note: we only allow a single thread in here at a time.
        """
        if not self.out_of_sync:
            return
        for collection_name in [ODL_NETWORKS, ODL_SUBNETS, ODL_PORTS]:
            self.sync_resources(collection_name, context)
        self.out_of_sync = False

    @staticmethod
    def filter_update_network_attributes(network, context):
        """Filter out network attributes for an update operation."""
        try_del(network, ['id', 'status', 'subnets', 'tenant_id'])

    @staticmethod
    def filter_update_subnet_attributes(subnet, context):
        """Filter out subnet attributes for an update operation."""
        try_del(subnet, ['id', 'network_id', 'ip_version', 'cidr',
                         'allocation_pools', 'tenant_id'])

    @classmethod
    def filter_update_port_attributes(cls, port, context):
        """Filter out port attributes for an update operation."""
        cls.add_security_groups(port, context)
        try_del(port, ['network_id', 'id', 'status', 'mac_address',
                       'tenant_id', 'fixed_ips'])

    def sync_single_resource(self, operation, object_type, context):
        """Sync over a single resource from Neutron to OpenDaylight.

        Handle syncing a single operation over to OpenDaylight, and correctly
        filter attributes out which are not required for the requisite
        operation (create or update) being handled.
        """
        try:
            obj_id = context.current['id']
            if operation == 'delete':
                self.sendjson('delete', object_type + '/' + obj_id, None)
            else:
                if operation == 'create':
                    urlpath = object_type
                    method = 'post'
                    attr_filter = self.create_object_map[object_type]
                elif operation == 'update':
                    urlpath = object_type + '/' + obj_id
                    method = 'put'
                    attr_filter = self.update_object_map[object_type]
                resource = context.current.copy()
                attr_filter(resource, context)
                self.sendjson(method, urlpath, {object_type[:-1]: resource})
        except Exception:
            with excutils.save_and_reraise_exception():
                self.out_of_sync = True

    @staticmethod
    def add_security_groups(port, context):
        """Populate the 'security_groups' field with entire records."""
        dbcontext = context._plugin_context
        groups = [context._plugin.get_security_group(dbcontext, sg)
                  for sg in port['security_groups']]
        port['security_groups'] = groups

    def sendjson(self, method, urlpath, obj):
        """Send json to the OpenDaylight controller."""
        headers = {'Content-Type': 'application/json'}
        data = jsonutils.dumps(obj, indent=2) if obj else None
        url = '/'.join([self.url, urlpath])
        LOG.debug("Sending METHOD (%(method)s) URL (%(url)s) JSON (%(obj)s)",
                  {'method': method, 'url': url, 'obj': obj})
        r = requests.request(method, url=url,
                             headers=headers, data=data,
                             auth=self.auth, timeout=self.timeout)
        r.raise_for_status()

    def bind_port(self, context):
        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        for segment in context.network.network_segments:
            if self.check_segment(segment):
                context.set_binding(segment[api.ID],
                                    self.vif_type,
                                    self.vif_details,
                                    status=n_const.PORT_STATUS_ACTIVE)
                LOG.debug("Bound using segment: %s", segment)
                return
            else:
                LOG.debug("Refusing to bind port for segment ID %(id)s, "
                          "segment %(seg)s, phys net %(physnet)s, and "
                          "network type %(nettype)s",
                          {'id': segment[api.ID],
                           'seg': segment[api.SEGMENTATION_ID],
                           'physnet': segment[api.PHYSICAL_NETWORK],
                           'nettype': segment[api.NETWORK_TYPE]})

    def check_segment(self, segment):
        """Verify a segment is valid for the OpenDaylight MechanismDriver.

        Verify the requested segment is supported by ODL and return True or
        False to indicate this to callers.
        """
        network_type = segment[api.NETWORK_TYPE]
        return network_type in [constants.TYPE_LOCAL, constants.TYPE_GRE,
                                constants.TYPE_VXLAN, constants.TYPE_VLAN]


OpenDaylightMechanismDriver.create_object_map = {
    ODL_NETWORKS: OpenDaylightMechanismDriver.filter_create_network_attributes,
    ODL_SUBNETS: OpenDaylightMechanismDriver.filter_create_subnet_attributes,
    ODL_PORTS: OpenDaylightMechanismDriver.filter_create_port_attributes}

OpenDaylightMechanismDriver.update_object_map = {
    ODL_NETWORKS: OpenDaylightMechanismDriver.filter_update_network_attributes,
    ODL_SUBNETS: OpenDaylightMechanismDriver.filter_update_subnet_attributes,
    ODL_PORTS: OpenDaylightMechanismDriver.filter_update_port_attributes}
