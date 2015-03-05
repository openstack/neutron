# Copyright 2014 VMware, Inc.
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

from vmware_nsx.neutron.plugins.vmware.plugins import base as nsx_mh

NsxMhPlugin = nsx_mh.NsxPluginV2
# The 'NsxPlugin' name will be deprecated in Liberty
# and replaced by the 'NsxMhPlugin' name
NsxPlugin = NsxMhPlugin
