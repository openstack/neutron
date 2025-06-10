..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)

==============================
Eventlet Deprecation Reference
==============================

This document contains the information related to the ``eventlet`` library
deprecation. Each section describes how each module has been migrated, the
caveats, the pending technical debt and the missing parts.


OVN Agent
---------

Launch process
~~~~~~~~~~~~~~

The execution of the OVN agent has been replaced. Instead of using
``oslo_services.launch``, that is still using eventlet, the agent creates
a ``threading.Event`` instance and holds the main thread execution by waiting
for this event.

.. note::

  Once the ``oslo_services`` library removes the usage of
  eventlet, the previous implementation will be restored. The
  ``oslo_services.service.ProcessLauncher`` service launcher implements a
  signal handler.


Metadata proxy
~~~~~~~~~~~~~~

The ``UnixDomainWSGIServer`` class has been replaced with a new implementation.
This implementation does not rely on ``neutron.api.wsgi.Server`` nor
``eventlet.wsgi.server``. It inherits from the built-in library class
``socketserver.StreamRequestHandler``.

.. note::

  This implementation doesn't use ``oslo_services`` to spawn the
  processes or the local threads depending on the ``metadata_workers``
  configuration variable. Right now only the embedded form (local thread)
  is implemented (``metadata_workers=0``, the default value). Future
  implementations will enable again this configuration variable.


OVN metadata agent
------------------

Metadata proxy
~~~~~~~~~~~~~~

The OVN metadata agent uses the same implementation as the OVN agent. The same
limitations apply.


Metadata agent
--------------

The Metadata agent uses the same implementation as the OVN agent and the same
limitations apply. The ``MetadataProxyHandler`` class is now instantiated every
time a new request is done; after the call, the instance is destroyed. The
cache used to store the previous RPC calls results is no longer relevant and
has been removed. In order to implement an RPC cache, it should be implemented
outside the mentioned class.


L3 agent
--------

The L3 agent now uses the ``oslo_service.backend.BackendType.THREADING``
backend, that doesn't import eventlet. The HA flavor replaces the
``UnixDomainWSGIServer`` with the ``UnixDomainWSGIThreadServer``. This new
Unix socket WSGI server is based on ``socketserver.ThreadingUnixStreamServer``
and doesn't use ``eventlet``.

Several functional and fullstack tests have been skipped until ``eventlet``
has been completely removed from the repository and the test frameworks. The
WSGI server cannot be spawned in an ``eventlet`` patched environment. The
thread that waits for new messages is a blocking function. In a kernel threads
environment, where the threads are preemptive, it is not needed to manually
yield the Python GIL; on the contrary, in an ``eventlet`` environment, the
threads must yield the executor to the next one.


Neutron API
-----------

The Neutron API currently can be executed only with the uWSGI module; the
eventlet executor has been deprecated, although the code has not been removed
from the repository yet. It is now mandatory to define the configuration
variable ``start-time`` in the uWSGI configuration file, using the magic
variable [1]_ "%t" that provides the *unix time (in seconds, gathered at
instance startup)*.

.. code::

  [uwsgi]
  start-time = %t


The Neutron API consists of the following executables:

* The API server: is a multiprocess worker; each process is created by the
  ``uWSGI`` server.

* The periodic worker: a mult process worker that spawns several threads to
  execute the periodic workers.

* The RPC worker: a multiprocess process worker that attends the requests from
  the RPC clients, for example the Neutron agents.

* The ML2/OVN maintenance worker: single process worker, needed by the ML2/OVN
  mechanism driver.


.. note::

  Right now, the API server, the OVN maintenance task and the periodic workers
  taks are running without eventlet.


ML2/OVN
~~~~~~~

The mechanism driver ML2/OVN requires a synchronization method between all
nodes (controllers) and workers. The OVN database events will be received by
all workers in all nodes; however, only one worker should process this event.
The ``HashRingManager``, locally instantiated in each worker, is in charge of
hashing the event received and decide what worker will process the event.

The ``HashRingManager`` uses the information stored in the Neutron database to
determine how many workers are alive at this time. Each worker will register
itself in the Neutron database, creating a register in the table
``ovn_hash_ring``. The UUID of each register is created using a deterministic
method that depends on (1) the hash ring group (always "mechanism_driver" for
the API workers), (2) the host name and (3) the worker ID. If the worker is
restarted, this method will provide the same register UUID and the previous
register (if present in the database) will be overwritten.


OVN maintenance task
~~~~~~~~~~~~~~~~~~~~

The ``OvnDbSynchronizer`` class now uses a ``threading.Thread`` to spawn the
``do_sync`` function. This is used by the Northbound and Southbound
synchronizer classes (``OvnNbSynchronizer``, ``OvnSbSynchronizer``).


.. note::

  The ``stop`` method needs to be refactored, along with the function
  ``do_sync`` implemented in each child class. The ``stop`` method needs to
  support a fast exit mechanism to stop as fast as possible the running
  synchronization.


Removals and deprecations
-------------------------

The ``api.wsgi.Server`` class, based on ``eventlet``, used in the Neutron API
and the Metadata server to handle multiple WSGI sockets, is removed from the
repository.


Testing
-------

Many tests are still not refactored to be compatible with the threading model
after the eventlet removal. Both in the unit test and the functional test
framework have been marked with the following message:

.. code::

  self.skipTest('This test is skipped after the eventlet removal and '
                'needs to be refactored')


Unit tests
~~~~~~~~~~

The ``py310`` job is unstable when executed with "concurrency=8" that is the
number of vCPUs of the CI virtual machines. It tends to timeout, most probably
because of a pending thread not being stopped. The ``tox.ini`` file enforces
this concurrency to 7 only for this job, running with Python 3.10.


Functional tests
~~~~~~~~~~~~~~~~

The main causes to skip the functional tests are:

* The lack of control over the kernel threads, in particular to end them. With
  eventlet it was possible to kill them, but this is no longer possible with
  the kernel threads. That leads to endless processing loops started by the
  tested modules that never end. The test could finish but ``stestr`` doesn't
  return a result until all threads are finished.

* The inability to spawn signal handlers out of the main thread. With eventlet,
  all the user threads were spawned on the main kernel thread. Without
  eventlet, some processes (e.g.: the OVS agent) are spawned in secondary
  threads but they fail because they are expecting to be executed by the main
  thread. That mainly affects the OVS agent testing in functional tests.

* The buggy os-ken implementation, that leads to random disconnections when
  executing the tests. The os-ken library is implemented to handle all the
  "applications" (processes with sockets open to the OF server). The new
  backend (using kernel threads) is not as stable as the eventlet one. During
  the application/OF server communication, some messages are lost and the
  communication is broken. That affects the OVS agent testing in functional
  tests.

It is also needed to handle the following issues that could affect the
performance and the stability of the system:

* Unclosed files. This warning message is repeated several times in the logs:

  :: code

    ResourceWarning: unclosed file <_io.FileIO name=55 mode='rb' closefd=True>
    ResourceWarning: Enable tracemalloc to get the object allocation traceback



References
----------

.. [1] https://uwsgi-docs.readthedocs.io/en/latest/Configuration.html#magic-variables
