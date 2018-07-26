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

import random
import time

from neutron_lib.db import api as db_api
from neutron_lib.services import base as service_base
from oslo_db import exception as db_exc
from oslo_log import log as logging
from sqlalchemy.orm import session as se

LOG = logging.getLogger(__name__)


class LokiPlugin(service_base.ServicePluginBase):
    """Loki brings us the gift of sporadic database failures and delays."""

    def __init__(self):
        super(LokiPlugin, self).__init__()
        db_api.sqla_listen(se.Session, 'before_flush', self.random_deadlock)
        db_api.sqla_listen(se.Session, 'loaded_as_persistent',
                           self.random_delay)

    def random_deadlock(self, session, flush_context, instances):
        if random.randrange(0, 51) > 49:  # 1/50 probability
            raise db_exc.DBDeadlock()

    def random_delay(self, session, instance):
        if random.randrange(0, 201) > 199:  # 1/200 probability
            LOG.debug("Loki has delayed loading of instance %s", instance)
            time.sleep(1)

    def get_plugin_type(self):
        return "loki"

    def get_plugin_description(self):
        return "Injects deadlocks and delays into database operations."
