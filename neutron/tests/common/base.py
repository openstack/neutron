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

from neutron.common import constants as n_const
from neutron.tests import base


def create_resource(prefix, creation_func, *args, **kwargs):
    """Create a new resource that does not already exist.

    :param prefix: The prefix for a randomly generated name
    :param creation_func: A function taking the name of the resource
           to be created as it's first argument.  An error is assumed
           to indicate a name collision.
    :param *args *kwargs: These will be passed to the create function.
    """
    while True:
        name = base.get_rand_name(
            max_length=n_const.DEVICE_NAME_MAX_LEN,
            prefix=prefix)
        try:
            return creation_func(name, *args, **kwargs)
        except RuntimeError:
            pass
