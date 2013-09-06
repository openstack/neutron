# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
#
# Author: Sylvain Afchain <sylvain.afchain@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Log helper functions."""

from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def log(method):
    """Decorator helping to log method calls."""
    def wrapper(*args, **kwargs):
        instance = args[0]
        data = {"class_name": (instance.__class__.__module__ + '.'
                               + instance.__class__.__name__),
                "method_name": method.__name__,
                "args": args[1:], "kwargs": kwargs}
        LOG.debug(_('%(class_name)s method %(method_name)s'
                    ' called with arguments %(args)s %(kwargs)s'), data)
        return method(*args, **kwargs)
    return wrapper
