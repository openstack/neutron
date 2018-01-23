# Copyright (c) 2015 Red Hat, Inc.
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

import os

from debtcollector import moves
from oslo_config import cfg
from ovs.db import idl
from ovs.stream import Stream
from ovsdbapp.backend.ovs_idl import connection as _connection
from ovsdbapp.backend.ovs_idl import idlutils
import tenacity

from neutron.agent.ovsdb.native import exceptions as ovsdb_exc
from neutron.agent.ovsdb.native import helpers

TransactionQueue = moves.moved_class(_connection.TransactionQueue,
                                     'TransactionQueue', __name__)
Connection = moves.moved_class(_connection.Connection, 'Connection', __name__)


def configure_ssl_conn():
    """
    Configures required settings for an SSL based OVSDB client connection
    :return: None
    """

    req_ssl_opts = {'ssl_key_file': cfg.CONF.OVS.ssl_key_file,
                    'ssl_cert_file': cfg.CONF.OVS.ssl_cert_file,
                    'ssl_ca_cert_file': cfg.CONF.OVS.ssl_ca_cert_file}
    for ssl_opt, ssl_file in req_ssl_opts.items():
        if not ssl_file:
            raise ovsdb_exc.OvsdbSslRequiredOptError(ssl_opt=ssl_opt)
        elif not os.path.exists(ssl_file):
            raise ovsdb_exc.OvsdbSslConfigNotFound(ssl_file=ssl_file)
    # TODO(ihrachys): move to ovsdbapp
    Stream.ssl_set_private_key_file(req_ssl_opts['ssl_key_file'])
    Stream.ssl_set_certificate_file(req_ssl_opts['ssl_cert_file'])
    Stream.ssl_set_ca_cert_file(req_ssl_opts['ssl_ca_cert_file'])


def idl_factory():
    conn = cfg.CONF.OVS.ovsdb_connection
    schema_name = 'Open_vSwitch'
    if conn.startswith('ssl:'):
        configure_ssl_conn()
    try:
        helper = idlutils.get_schema_helper(conn, schema_name)
    except Exception:
        helpers.enable_connection_uri(conn)

        @tenacity.retry(wait=tenacity.wait_exponential(multiplier=0.01),
                        stop=tenacity.stop_after_delay(1),
                        reraise=True)
        def do_get_schema_helper():
            return idlutils.get_schema_helper(conn, schema_name)

        helper = do_get_schema_helper()

    # TODO(twilson) We should still select only the tables/columns we use
    helper.register_all()
    return idl.Idl(conn, helper)
