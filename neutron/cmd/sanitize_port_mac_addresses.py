#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from neutron_lib.api import converters
from neutron_lib import context
from neutron_lib.db import api as db_api
from oslo_config import cfg
from oslo_db import options as db_options
from oslo_log import log as logging

from neutron.db import models_v2


LOG = logging.getLogger(__name__)


def setup_conf():
    conf = cfg.CONF
    db_group, neutron_db_opts = db_options.list_opts()[0]
    cfg.CONF.register_cli_opts(neutron_db_opts, db_group)
    conf()


def main():
    """Main method for sanitizing the database ``port.mac_address`` column.

    This script will sanitize all ``port.mac_address`` columns existing in the
    database. The output format will be xx:xx:xx:xx:xx:xx.
    """
    setup_conf()
    admin_ctx = context.get_admin_context()
    with db_api.CONTEXT_WRITER.using(admin_ctx):
        for port in admin_ctx.session.query(models_v2.Port.id,
                                            models_v2.Port.mac_address).all():
            if port[1] == converters.convert_to_sanitized_mac_address(port[1]):
                continue

            query = admin_ctx.session.query(models_v2.Port)
            port_db = query.filter(models_v2.Port.id == port[0]).first()
            if not port_db:
                continue

            mac_address = converters.convert_to_sanitized_mac_address(port[1])
            port_db.update({'mac_address': mac_address})
            LOG.info('Port %s updated, MAC address: %s', port[0],
                     mac_address)
