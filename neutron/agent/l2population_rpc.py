# Copyright (c) 2013 OpenStack Foundation.
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
#
# @author: Sylvain Afchain, eNovance SAS
# @author: Francois Eleouet, Orange
# @author: Mathieu Rohon, Orange

import abc

from oslo.config import cfg
import six

from neutron.common import log


@six.add_metaclass(abc.ABCMeta)
class L2populationRpcCallBackMixin(object):

    @log.log
    def add_fdb_entries(self, context, fdb_entries, host=None):
        if not host or host == cfg.CONF.host:
            self.fdb_add(context, fdb_entries)

    @log.log
    def remove_fdb_entries(self, context, fdb_entries, host=None):
        if not host or host == cfg.CONF.host:
            self.fdb_remove(context, fdb_entries)

    @log.log
    def update_fdb_entries(self, context, fdb_entries, host=None):
        if not host or host == cfg.CONF.host:
            self.fdb_update(context, fdb_entries)

    @abc.abstractmethod
    def fdb_add(self, context, fdb_entries):
        pass

    @abc.abstractmethod
    def fdb_remove(self, context, fdb_entries):
        pass

    @abc.abstractmethod
    def fdb_update(self, context, fdb_entries):
        pass
