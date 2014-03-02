# Copyright 2012 VMware, Inc.
#
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
#

from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def find_version(headers):
    """Retrieve NSX controller version from response headers."""
    for (header_name, header_value) in (headers or ()):
        try:
            if header_name == 'server':
                return Version(header_value.split('/')[1])
        except IndexError:
            LOG.warning(_("Unable to fetch NSX version from response "
                          "headers :%s"), headers)


class Version(object):
    """Abstracts NSX version by exposing major and minor."""

    def __init__(self, version):
        self.full_version = version.split('.')
        self.major = int(self.full_version[0])
        self.minor = int(self.full_version[1])

    def __str__(self):
        return '.'.join(self.full_version)
