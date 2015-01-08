# Copyright 2014 VMware, Inc.
# All Rights Reserved
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

from oslo_serialization import jsonutils
from oslo_utils import excutils

from neutron.api.v2 import attributes as attr
from neutron.common import exceptions as exception
from neutron.openstack.common import log
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.common import utils
from neutron.plugins.vmware import nsxlib

HTTP_POST = "POST"
HTTP_DELETE = "DELETE"

LQUEUE_RESOURCE = "lqueue"

LOG = log.getLogger(__name__)


def create_lqueue(cluster, queue_data):
    params = {
        'name': 'display_name',
        'qos_marking': 'qos_marking',
        'min': 'min_bandwidth_rate',
        'max': 'max_bandwidth_rate',
        'dscp': 'dscp'
    }
    queue_obj = dict(
        (nsx_name, queue_data.get(api_name))
        for api_name, nsx_name in params.iteritems()
        if attr.is_attr_set(queue_data.get(api_name))
    )
    if 'display_name' in queue_obj:
        queue_obj['display_name'] = utils.check_and_truncate(
            queue_obj['display_name'])

    queue_obj['tags'] = utils.get_tags()
    try:
        return nsxlib.do_request(HTTP_POST,
                                 nsxlib._build_uri_path(LQUEUE_RESOURCE),
                                 jsonutils.dumps(queue_obj),
                                 cluster=cluster)['uuid']
    except api_exc.NsxApiException:
        # FIXME(salv-orlando): This should not raise NeutronException
        with excutils.save_and_reraise_exception():
            raise exception.NeutronException()


def delete_lqueue(cluster, queue_id):
    try:
        nsxlib.do_request(HTTP_DELETE,
                          nsxlib._build_uri_path(LQUEUE_RESOURCE,
                                                 resource_id=queue_id),
                          cluster=cluster)
    except Exception:
        # FIXME(salv-orlando): This should not raise NeutronException
        with excutils.save_and_reraise_exception():
            raise exception.NeutronException()
