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
import threading
import traceback

from debtcollector import removals
from ovs.db import idl
from ovs import poller
import six
from six.moves import queue as Queue

from neutron._i18n import _
from neutron.agent.ovsdb.native import idlutils


class TransactionQueue(Queue.Queue, object):
    def __init__(self, *args, **kwargs):
        super(TransactionQueue, self).__init__(*args, **kwargs)
        alertpipe = os.pipe()
        # NOTE(ivasilevskaya) python 3 doesn't allow unbuffered I/O. Will get
        # around this constraint by using binary mode.
        self.alertin = os.fdopen(alertpipe[0], 'rb', 0)
        self.alertout = os.fdopen(alertpipe[1], 'wb', 0)

    def get_nowait(self, *args, **kwargs):
        try:
            result = super(TransactionQueue, self).get_nowait(*args, **kwargs)
        except Queue.Empty:
            return None
        self.alertin.read(1)
        return result

    def put(self, *args, **kwargs):
        super(TransactionQueue, self).put(*args, **kwargs)
        self.alertout.write(six.b('X'))
        self.alertout.flush()

    @property
    def alert_fileno(self):
        return self.alertin.fileno()


class Connection(object):
    __rm_args = {'version': 'Ocata', 'removal_version': 'Pike',
                 'message': _('Use an idl_factory function instead')}

    @removals.removed_kwarg('connection', **__rm_args)
    @removals.removed_kwarg('schema_name', **__rm_args)
    @removals.removed_kwarg('idl_class', **__rm_args)
    def __init__(self, connection=None, timeout=None, schema_name=None,
                 idl_class=None, idl_factory=None):
        """Create a connection to an OVSDB server using the OVS IDL

        :param connection: (deprecated) An OVSDB connection string
        :param timeout: The timeout value for OVSDB operations (required)
        :param schema_name: (deprecated) The name ovs the OVSDB schema to use
        :param idl_class: (deprecated) An Idl subclass. Defaults to idl.Idl
        :param idl_factory: A factory function that produces an Idl instance

        The signature of this class is changing. It is recommended to pass in
        a timeout and idl_factory
        """
        assert timeout is not None
        self.idl = None
        self.timeout = timeout
        self.txns = TransactionQueue(1)
        self.lock = threading.Lock()
        if idl_factory:
            if connection or schema_name:
                raise TypeError(_('Connection: Takes either idl_factory, or '
                                  'connection and schema_name. Both given'))
            self.idl_factory = idl_factory
        else:
            if not connection or not schema_name:
                raise TypeError(_('Connection: Takes either idl_factory, or '
                                  'connection and schema_name. Neither given'))
            self.idl_factory = self._idl_factory
            self.connection = connection
            self.schema_name = schema_name
            self.idl_class = idl_class or idl.Idl
            self._schema_filter = None

    @removals.remove(**__rm_args)
    def _idl_factory(self):
        helper = self.get_schema_helper()
        self.update_schema_helper(helper)
        return self.idl_class(self.connection, helper)

    @removals.removed_kwarg('table_name_list', **__rm_args)
    def start(self, table_name_list=None):
        """
        :param table_name_list: A list of table names for schema_helper to
                register. When this parameter is given, schema_helper will only
                register tables which name are in list. Otherwise,
                schema_helper will register all tables for given schema_name as
                default.
        """
        self._schema_filter = table_name_list
        with self.lock:
            if self.idl is not None:
                return

            self.idl = self.idl_factory()
            idlutils.wait_for_change(self.idl, self.timeout)
            self.poller = poller.Poller()
            self.thread = threading.Thread(target=self.run)
            self.thread.setDaemon(True)
            self.thread.start()

    @removals.remove(
        version='Ocata', removal_version='Pike',
        message=_("Use idlutils.get_schema_helper(conn, schema, retry=True)"))
    def get_schema_helper(self):
        """Retrieve the schema helper object from OVSDB"""
        return idlutils.get_schema_helper(self.connection, self.schema_name,
                                          retry=True)

    @removals.remove(
        version='Ocata', removal_version='Pike',
        message=_("Use an idl_factory and ovs.db.SchemaHelper for filtering"))
    def update_schema_helper(self, helper):
        if self._schema_filter:
            for table_name in self._schema_filter:
                helper.register_table(table_name)
        else:
            helper.register_all()

    def run(self):
        while True:
            self.idl.wait(self.poller)
            self.poller.fd_wait(self.txns.alert_fileno, poller.POLLIN)
            #TODO(jlibosva): Remove next line once losing connection to ovsdb
            #                is solved.
            self.poller.timer_wait(self.timeout * 1000)
            self.poller.block()
            self.idl.run()
            txn = self.txns.get_nowait()
            if txn is not None:
                try:
                    txn.results.put(txn.do_commit())
                except Exception as ex:
                    er = idlutils.ExceptionResult(ex=ex,
                                                  tb=traceback.format_exc())
                    txn.results.put(er)
                self.txns.task_done()

    def queue_txn(self, txn):
        self.txns.put(txn)
