# Copyright 2017 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hashlib
import hmac
import threading
import urllib

from neutron._i18n import _
from neutron.agent.linux import utils as agent_utils
from neutron.agent.ovn.metadata import ovsdb
from neutron.common import ipv6_utils
from neutron.common.ovn import constants as ovn_const
from neutron.conf.agent.metadata import config
from neutron_lib.callbacks import events
from neutron_lib.callbacks import registry
from neutron_lib.callbacks import resources
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import encodeutils
import requests
import webob


LOG = logging.getLogger(__name__)

MODE_MAP = {
    config.USER_MODE: 0o644,
    config.GROUP_MODE: 0o664,
    config.ALL_MODE: 0o666,
}


class MetadataProxyHandler(object):

    def __init__(self, conf, chassis):
        self.conf = conf
        self.chassis = chassis
        self._sb_idl = None
        self._post_fork_event = threading.Event()
        self.subscribe()

    @property
    def sb_idl(self):
        if not self._sb_idl:
            self._post_fork_event.wait()

        return self._sb_idl

    @sb_idl.setter
    def sb_idl(self, val):
        self._sb_idl = val

    def subscribe(self):
        registry.subscribe(self.post_fork_initialize,
                           resources.PROCESS,
                           events.AFTER_INIT)

    def post_fork_initialize(self, resource, event, trigger, payload=None):
        # We need to open a connection to OVN SouthBound database for
        # each worker so that we can process the metadata requests.
        self._post_fork_event.clear()
        self.sb_idl = ovsdb.MetadataAgentOvnSbIdl(
            tables=('Port_Binding', 'Datapath_Binding', 'Chassis'),
            chassis=self.chassis).start()

        # Now IDL connections can be safely used.
        self._post_fork_event.set()

    @webob.dec.wsgify(RequestClass=webob.Request)
    def __call__(self, req):
        try:
            LOG.debug("Request: %s", req)

            instance_id, project_id = self._get_instance_and_project_id(req)
            if instance_id:
                return self._proxy_request(instance_id, project_id, req)
            else:
                return webob.exc.HTTPNotFound()

        except Exception:
            LOG.exception("Unexpected error.")
            msg = _('An unknown error has occurred. '
                    'Please try your request again.')
            explanation = str(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)

    def _get_instance_and_project_id(self, req):
        remote_address = req.headers.get('X-Forwarded-For')
        network_id = req.headers.get('X-OVN-Network-ID')

        ports = self.sb_idl.get_network_port_bindings_by_ip(network_id,
                                                            remote_address)
        num_ports = len(ports)
        if num_ports == 1:
            external_ids = ports[0].external_ids
            return (external_ids[ovn_const.OVN_DEVID_EXT_ID_KEY],
                    external_ids[ovn_const.OVN_PROJID_EXT_ID_KEY])
        elif num_ports == 0:
            LOG.error("No port found in network %s with IP address %s",
                      network_id, remote_address)
        elif num_ports > 1:
            port_uuids = ', '.join([str(port.uuid) for port in ports])
            LOG.error("More than one port found in network %s with IP address "
                      "%s. Please run the neutron-ovn-db-sync-util script as "
                      "there seems to be inconsistent data between Neutron "
                      "and OVN databases. OVN Port uuids: %s", network_id,
                      remote_address, port_uuids)

        return None, None

    def _proxy_request(self, instance_id, tenant_id, req):
        headers = {
            'X-Forwarded-For': req.headers.get('X-Forwarded-For'),
            'X-Instance-ID': instance_id,
            'X-Tenant-ID': tenant_id,
            'X-Instance-ID-Signature': self._sign_instance_id(instance_id)
        }

        nova_host_port = ipv6_utils.valid_ipv6_url(
            self.conf.nova_metadata_host,
            self.conf.nova_metadata_port)

        url = urllib.parse.urlunsplit((
            self.conf.nova_metadata_protocol,
            nova_host_port,
            req.path_info,
            req.query_string,
            ''))

        disable_ssl_certificate_validation = self.conf.nova_metadata_insecure
        if self.conf.auth_ca_cert and not disable_ssl_certificate_validation:
            verify_cert = self.conf.auth_ca_cert
        else:
            verify_cert = not disable_ssl_certificate_validation

        client_cert = None
        if self.conf.nova_client_cert and self.conf.nova_client_priv_key:
            client_cert = (self.conf.nova_client_cert,
                           self.conf.nova_client_priv_key)

        resp = requests.request(method=req.method, url=url,
                                headers=headers,
                                data=req.body,
                                cert=client_cert,
                                verify=verify_cert)

        if resp.status_code == 200:
            req.response.content_type = resp.headers['content-type']
            req.response.body = resp.content
            LOG.debug(str(resp))
            return req.response
        elif resp.status_code == 403:
            LOG.warning(
                'The remote metadata server responded with Forbidden. This '
                'response usually occurs when shared secrets do not match.'
            )
            return webob.exc.HTTPForbidden()
        elif resp.status_code == 400:
            return webob.exc.HTTPBadRequest()
        elif resp.status_code == 404:
            return webob.exc.HTTPNotFound()
        elif resp.status_code == 409:
            return webob.exc.HTTPConflict()
        elif resp.status_code == 500:
            msg = _(
                'Remote metadata server experienced an internal server error.'
            )
            LOG.warning(msg)
            explanation = str(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)
        else:
            raise Exception(_('Unexpected response code: %s') %
                            resp.status_code)

    def _sign_instance_id(self, instance_id):
        secret = self.conf.metadata_proxy_shared_secret
        secret = encodeutils.to_utf8(secret)
        instance_id = encodeutils.to_utf8(instance_id)
        return hmac.new(secret, instance_id, hashlib.sha256).hexdigest()


class UnixDomainMetadataProxy(object):

    def __init__(self, conf, chassis):
        self.conf = conf
        self.chassis = chassis
        agent_utils.ensure_directory_exists_without_file(
            cfg.CONF.metadata_proxy_socket)

    def _get_socket_mode(self):
        mode = self.conf.metadata_proxy_socket_mode
        if mode == config.DEDUCE_MODE:
            user = self.conf.metadata_proxy_user
            if (not user or user == '0' or user == 'root' or
                    agent_utils.is_effective_user(user)):
                # user is agent effective user or root => USER_MODE
                mode = config.USER_MODE
            else:
                group = self.conf.metadata_proxy_group
                if not group or agent_utils.is_effective_group(group):
                    # group is agent effective group => GROUP_MODE
                    mode = config.GROUP_MODE
                else:
                    # otherwise => ALL_MODE
                    mode = config.ALL_MODE
        return MODE_MAP[mode]

    def run(self):
        self.server = agent_utils.UnixDomainWSGIServer(
            'neutron-ovn-metadata-agent')
        # Set the default metadata_workers if not yet set in the config file
        md_workers = self.conf.metadata_workers
        if md_workers is None:
            md_workers = 2
        self.server.start(MetadataProxyHandler(self.conf, self.chassis),
                          self.conf.metadata_proxy_socket,
                          workers=md_workers,
                          backlog=self.conf.metadata_backlog,
                          mode=self._get_socket_mode())

    def wait(self):
        self.server.wait()
