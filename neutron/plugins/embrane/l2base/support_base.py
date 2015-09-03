# Copyright 2013 Embrane, Inc.
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

import six


@six.add_metaclass(abc.ABCMeta)
class SupportBase(object):
    """abstract support class.

    Defines the methods a plugin support should implement to be used as
    the L2 base for Embrane plugin.

    """

    @abc.abstractmethod
    def __init__(self):
        pass

    @abc.abstractmethod
    def retrieve_utif_info(self, context, neutron_port=None, network=None):
        """Retrieve specific network info.

        each plugin support, querying its own DB, can collect all the
        information needed by the ESM in order to create the
        user traffic security zone.

        :param interface_info: the foo parameter
        :param context: neutron request context
        :returns: heleosapi.info.UtifInfo -- specific network info
        :raises: UtifInfoError
        """
