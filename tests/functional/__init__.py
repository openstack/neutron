# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Somebody PLC
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

"""
Base test class for running non-stubbed tests (functional tests)

The FunctionalTest class contains helper methods for starting the API
and Registry server, grabbing the logs of each, cleaning up pidfiles,
and spinning down the servers.
"""

import datetime
import functools
import os
import random
import shutil
import signal
import socket
import tempfile
import time
import unittest
import urlparse

from tests.utils import execute, get_unused_port

from sqlalchemy import create_engine


class Server(object):
    """
    Class used to easily manage starting and stopping
    a server during functional test runs.
    """
    def __init__(self, test_dir, port):
        """
        Creates a new Server object.

        :param test_dir: The directory where all test stuff is kept. This is
                         passed from the FunctionalTestCase.
        :param port: The port to start a server up on.
        """
        self.verbose = True
        self.debug = True
        self.test_dir = test_dir
        self.bind_port = port
        self.conf_file = None
        self.conf_base = None

    def start(self, **kwargs):
        """
        Starts the server.

        Any kwargs passed to this method will override the configuration
        value in the conf file used in starting the servers.
        """
        if self.conf_file:
            raise RuntimeError("Server configuration file already exists!")
        if not self.conf_base:
            raise RuntimeError("Subclass did not populate config_base!")

        conf_override = self.__dict__.copy()
        if kwargs:
            conf_override.update(**kwargs)

        # Create temporary configuration file for Quantum Unit tests.

        conf_file = tempfile.NamedTemporaryFile()
        conf_file.write(self.conf_base % conf_override)
        conf_file.flush()
        self.conf_file = conf_file
        self.conf_file_name = conf_file.name

        cmd = ("./bin/quantum %(conf_file_name)s" % self.__dict__)
        return execute(cmd)

    def stop(self):
        """
        Spin down the server.
        """
        # The only way we can do that at the moment is by killing quantum
        # TODO - find quantum PID and do a sudo kill


class ApiServer(Server):

    """
    Server object that starts/stops/manages the API server
    """

    def __init__(self, test_dir, port, registry_port):
        super(ApiServer, self).__init__(test_dir, port)
        self.server_name = 'api'
        self.default_store = 'file'
        self.image_dir = os.path.join(self.test_dir,
                                         "images")
        self.pid_file = os.path.join(self.test_dir,
                                         "api.pid")
        self.log_file = os.path.join(self.test_dir, "api.log")
        self.registry_port = registry_port
        self.conf_base = """[DEFAULT]
verbose = %(verbose)s
debug = %(debug)s
filesystem_store_datadir=%(image_dir)s
default_store = %(default_store)s
bind_host = 0.0.0.0
bind_port = %(bind_port)s
registry_host = 0.0.0.0
registry_port = %(registry_port)s
log_file = %(log_file)s

[pipeline:glance-api]
pipeline = versionnegotiation apiv1app

[pipeline:versions]
pipeline = versionsapp

[app:versionsapp]
paste.app_factory = glance.api.versions:app_factory

[app:apiv1app]
paste.app_factory = glance.api.v1:app_factory

[filter:versionnegotiation]
paste.filter_factory = glance.api.middleware.version_negotiation:filter_factory
"""


class QuantumAPIServer(Server):

    """
    Server object that starts/stops/manages the Quantum API Server
    """

    def __init__(self, test_dir, port):
        super(QuantumAPIServer, self).__init__(test_dir, port)

        self.db_file = os.path.join(self.test_dir, ':memory:')
        self.sql_connection = 'sqlite:///%s' % self.db_file
        self.conf_base = """[DEFAULT]
# Show more verbose log output (sets INFO log level output)
verbose = %(verbose)s
# Show debugging output in logs (sets DEBUG log level output)
debug = %(debug)s
# Address to bind the API server
bind_host = 0.0.0.0
# Port for test API server
bind_port = %(bind_port)s

[composite:quantum]
use = egg:Paste#urlmap
/: quantumversions
/v0.1: quantumapi

[app:quantumversions]
paste.app_factory = quantum.api.versions:Versions.factory

[app:quantumapi]
paste.app_factory = quantum.api:APIRouterV01.factory
"""


class FunctionalTest(unittest.TestCase):

    """
    Base test class for any test that wants to test the actual
    servers and clients and not just the stubbed out interfaces
    """

    def setUp(self):

        self.test_id = random.randint(0, 100000)
        self.test_port = get_unused_port()

        self.quantum_server = QuantumAPIServer(self.test_dir,
                                               self.test_port)

    def tearDown(self):
        self.cleanup()
        # We destroy the test data store between each test case,
        # and recreate it, which ensures that we have no side-effects
        # from the tests
        self._reset_database()

    def _reset_database(self):
        conn_string = self.registry_server.sql_connection
        conn_pieces = urlparse.urlparse(conn_string)
        if conn_string.startswith('sqlite'):
            # We can just delete the SQLite database, which is
            # the easiest and cleanest solution
            db_path = conn_pieces.path.strip('/')
            if db_path and os.path.exists(db_path):
                os.unlink(db_path)
            # No need to recreate the SQLite DB. SQLite will
            # create it for us if it's not there...
        elif conn_string.startswith('mysql'):
            # We can execute the MySQL client to destroy and re-create
            # the MYSQL database, which is easier and less error-prone
            # than using SQLAlchemy to do this via MetaData...trust me.
            database = conn_pieces.path.strip('/')
            loc_pieces = conn_pieces.netloc.split('@')
            host = loc_pieces[1]
            auth_pieces = loc_pieces[0].split(':')
            user = auth_pieces[0]
            password = ""
            if len(auth_pieces) > 1:
                if auth_pieces[1].strip():
                    password = "-p%s" % auth_pieces[1]
            sql = ("drop database if exists %(database)s; "
                   "create database %(database)s;") % locals()
            cmd = ("mysql -u%(user)s %(password)s -h%(host)s "
                   "-e\"%(sql)s\"") % locals()
            exitcode, out, err = execute(cmd)
            self.assertEqual(0, exitcode)

    def start_servers(self, **kwargs):
        """
        Starts the Quantum API server on an unused port.

        Any kwargs passed to this method will override the configuration
        value in the conf file used in starting the server.
        """

        exitcode, out, err = self.quantum_server.start(**kwargs)

        self.assertEqual(0, exitcode,
                         "Failed to spin up the Quantum server. "
                         "Got: %s" % err)
        #self.assertTrue("Starting quantum with" in out)
        #TODO: replace with appropriate assert

        self.wait_for_servers()

    def ping_server(self, port):
        """
        Simple ping on the port. If responsive, return True, else
        return False.

        :note We use raw sockets, not ping here, since ping uses ICMP and
        has no concept of ports...
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(("127.0.0.1", port))
            s.close()
            return True
        except socket.error, e:
            return False

    def wait_for_servers(self, timeout=3):
        """
        Tight loop, waiting for both API and registry server to be
        available on the ports. Returns when both are pingable. There
        is a timeout on waiting for the servers to come up.

        :param timeout: Optional, defaults to 3 seconds
        """
        now = datetime.datetime.now()
        timeout_time = now + datetime.timedelta(seconds=timeout)
        while (timeout_time > now):
            if self.ping_server(self.api_port) and\
               self.ping_server(self.registry_port):
                return
            now = datetime.datetime.now()
            time.sleep(0.05)
        self.assertFalse(True, "Failed to start servers.")

    def stop_servers(self):
        """
        Called to stop the started servers in a normal fashion. Note
        that cleanup() will stop the servers using a fairly draconian
        method of sending a SIGTERM signal to the servers. Here, we use
        the glance-control stop method to gracefully shut the server down.
        This method also asserts that the shutdown was clean, and so it
        is meant to be called during a normal test case sequence.
        """

        exitcode, out, err = self.quantum_server.stop()
        self.assertEqual(0, exitcode,
                         "Failed to spin down the Quantum server. "
                         "Got: %s" % err)
