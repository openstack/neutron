# Copyright (c) 2017 Huawei Technology, Inc.  All rights reserved.
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

from neutron_lib.api import extensions
from oslo_config import cfg
from oslo_log import log as logging

from neutron.extensions import _filter_validation_lib as apidef


LOG = logging.getLogger(__name__)


def _disable_extension_by_config(aliases):
    if not cfg.CONF.filter_validation:
        if 'filter-validation' in aliases:
            aliases.remove('filter-validation')
        LOG.info('Disabled filter validation extension.')


class Filter_validation(extensions.APIExtensionDescriptor):
    """Extension class supporting filter validation."""

    api_definition = apidef
