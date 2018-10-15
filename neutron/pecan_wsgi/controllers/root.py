# Copyright (c) 2015 Mirantis, Inc.
# Copyright (c) 2015 Rackspace, Inc.
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

from neutron_lib.api.definitions import network as net_def
from neutron_lib.api.definitions import port as port_def
from neutron_lib.api.definitions import subnet as subnet_def
from neutron_lib.api.definitions import subnetpool as subnetpool_def
from oslo_config import cfg
from oslo_log import log
import pecan
from pecan import request
from six.moves import urllib

from neutron._i18n import _
from neutron.api.views import versions as versions_view
from neutron import manager
from neutron.pecan_wsgi.controllers import extensions as ext_ctrl
from neutron.pecan_wsgi.controllers import utils


CONF = cfg.CONF

LOG = log.getLogger(__name__)
_VERSION_INFO = {}
_CORE_RESOURCES = {net_def.RESOURCE_NAME: net_def.COLLECTION_NAME,
                   subnet_def.RESOURCE_NAME: subnet_def.COLLECTION_NAME,
                   subnetpool_def.RESOURCE_NAME:
                       subnetpool_def.COLLECTION_NAME,
                   port_def.RESOURCE_NAME: port_def.COLLECTION_NAME}


def _load_version_info(version_info):
    if version_info['id'] in _VERSION_INFO:
        raise AssertionError(_("ID %s must not be in "
                               "VERSION_INFO") % version_info['id'])
    _VERSION_INFO[version_info['id']] = version_info


def _get_version_info():
    return _VERSION_INFO.values()


class RootController(object):

    @utils.expose(generic=True)
    def index(self):
        version_objs = [
            {
                "id": "v2.0",
                "status": "CURRENT",
            },
        ]
        builder = versions_view.get_view_builder(pecan.request)
        versions = [builder.build(version) for version in version_objs]
        return dict(versions=versions)

    @utils.when(index, method='HEAD')
    @utils.when(index, method='POST')
    @utils.when(index, method='PATCH')
    @utils.when(index, method='PUT')
    @utils.when(index, method='DELETE')
    def not_supported(self):
        pecan.abort(405)


class V2Controller(object):

    # Same data structure as neutron.api.versions.Versions for API backward
    # compatibility
    version_info = {
        'id': 'v2.0',
        'status': 'CURRENT'
    }
    _load_version_info(version_info)

    # NOTE(blogan): Paste deploy handled the routing to the legacy extension
    # controller.  If the extensions filter is removed from the api-paste.ini
    # then this controller will be routed to  This means operators had
    # the ability to turn off the extensions controller via tha api-paste but
    # will not be able to turn it off with the pecan switch.
    extensions = ext_ctrl.ExtensionsController()

    @utils.expose(generic=True)
    def index(self):
        if not pecan.request.path_url.endswith('/'):
            pecan.abort(404)

        layout = []
        for name, collection in _CORE_RESOURCES.items():
            href = urllib.parse.urljoin(pecan.request.path_url, collection)
            resource = {'name': name,
                        'collection': collection,
                        'links': [{'rel': 'self',
                                   'href': href}]}
            layout.append(resource)
        return {'resources': layout}

    @utils.when(index, method='HEAD')
    @utils.when(index, method='POST')
    @utils.when(index, method='PATCH')
    @utils.when(index, method='PUT')
    @utils.when(index, method='DELETE')
    def not_supported(self):
        pecan.abort(405)

    @utils.expose()
    def _lookup(self, collection, *remainder):
        # if collection exists in the extension to service plugins map then
        # we are assuming that collection is the service plugin and
        # needs to be remapped.
        # Example: https://neutron.endpoint/v2.0/lbaas/loadbalancers
        if (remainder and
                manager.NeutronManager.get_resources_for_path_prefix(
                    collection)):
            collection = remainder[0]
            remainder = remainder[1:]
        controller = manager.NeutronManager.get_controller_for_resource(
            collection)
        if not controller:
            LOG.warning("No controller found for: %s - returning response "
                        "code 404", collection)
            pecan.abort(404)
        # Store resource and collection names in pecan request context so that
        # hooks can leverage them if necessary. The following code uses
        # attributes from the controller instance to ensure names have been
        # properly sanitized (eg: replacing dashes with underscores)
        request.context['resource'] = controller.resource
        request.context['collection'] = controller.collection
        # NOTE(blogan): initialize a dict to store the ids of the items walked
        # in the path for example: /networks/1234 would cause uri_identifiers
        # to contain: {'network_id': '1234'}
        # This is for backwards compatibility with legacy extensions that
        # defined their own controllers and expected kwargs to be passed in
        # with the uri_identifiers
        request.context['uri_identifiers'] = {}
        return controller, remainder
