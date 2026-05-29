.. _config-wsgi:

WSGI Usage with the Neutron API
===============================

This document is a guide to deploying Neutron using WSGI. There are two ways to
deploy using WSGI: ``uwsgi`` and Apache ``mod_wsgi``.

Please note that if you intend to use mode uwsgi, you should install the
``mode_proxy_uwsgi`` module. For example on deb-based system:

.. code-block:: console

    # sudo apt-get install libapache2-mod-proxy-uwsgi
    # sudo a2enmod proxy
    # sudo a2enmod proxy_uwsgi

.. end

WSGI Application
----------------

The function ``neutron.server.get_application`` will setup a WSGI application
to run behind a WSGI server like uwsgi or mod_wsgi.

Neutron API behind uwsgi
------------------------

Create a ``/etc/neutron/neutron-api-uwsgi.ini`` file with the content below:

.. code-block:: ini

    [uwsgi]
    chmod-socket = 666
    socket = /var/run/uwsgi/neutron-api.socket
    start-time = %t
    lazy-apps = true
    add-header = Connection: close
    buffer-size = 65535
    hook-master-start = unix_signal:15 gracefully_kill_them_all
    thunder-lock = true
    plugins = http,python3
    enable-threads = true
    worker-reload-mercy = 80
    exit-on-reload = false
    die-on-term = true
    master = true
    processes = 2
    module = neutron.wsgi.api:application

.. end

Start neutron-api:

.. code-block:: console

    # uwsgi --procname-prefix neutron-api --ini /etc/neutron/neutron-api-uwsgi.ini

.. end


Start Neutron RPC server
------------------------

When Neutron API is served by a web server (like Apache2) it is difficult
to start an rpc listener thread. So start the Neutron RPC server process to
serve this job:

.. code-block:: console

    # /usr/bin/neutron-rpc-server --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini

.. end

Start Neutron periodic workers
------------------------------

When Neutron API is served by a web server, ML2 plugin periodic tasks are
started in a dedicated process:

.. code-block:: console

    # /usr/bin/neutron-periodic-workers --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini

.. end

This process collects plugin workers registered through ``get_workers()`` and
starts them according to their ``worker_process_count`` value:

* Workers with ``worker_process_count=0`` are grouped inside a single
  ``AllServicesNeutronWorker`` and executed as threads in one child process.
  This is appropriate for interval-based ``PeriodicWorker`` tasks such as quota
  cleanup, L3 garbage collection, and agent health checks. These workers call
  ``start()`` and return; their ``wait()`` method only blocks while the
  periodic loop is running, which is safe inside the grouped thread model.
* Workers with ``worker_process_count>0`` are started in separate child
  processes, one per worker definition. Plugin workers whose ``wait()`` method
  blocks indefinitely on a long-running service must use
  ``worker_process_count=1``, the same model as ``RpcWorker``. Examples include
  the L3 and metering ``RpcWorker`` instances and the BGP worker.

Plugin authors returning workers from ``get_workers()`` must set
``worker_process_count=1`` for any worker that blocks on ``wait()`` after
``start()``. Grouping such workers with ``worker_process_count=0`` would
prevent other grouped workers from making progress.

The following worker types are not started by this process:

* ``MaintenanceWorker`` from the ML2/OVN mechanism driver. This worker is
  started by ``neutron-ovn-maintenance-worker``.
* ``AllServicesNeutronWorker`` instances, if returned directly by a plugin.

Start Neutron OVN maintenance worker
------------------------------------

When the ML2/OVN mechanism driver is used, the database maintenance task runs
in a dedicated process:

.. code-block:: console

    # /usr/bin/neutron-ovn-maintenance-worker --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini

.. end

Neutron Worker Processes
------------------------

In a WSGI deployment, Neutron splits background work across several
executables in addition to the API server:

* ``neutron-rpc-server``: handles RPC requests from agents.
* ``neutron-periodic-workers``: handles ML2 plugin periodic and thread
  workers.
* ``neutron-ovn-maintenance-worker``: handles the ML2/OVN database
  maintenance task when that mechanism driver is enabled.

The RPC server will attempt to spawn a number of child processes for handling
RPC requests. The number of API workers is set to the number of CPU cores,
further limited by available memory, and the number of RPC workers is set to
half that number.

It is strongly recommended that all deployers set these values themselves,
via the api_workers and rpc_workers configuration parameters.

For a cloud with a high load to a relatively small number of objects,
a smaller value for api_workers will provide better performance than
many (somewhere around 4-8.) For a cloud with a high load to lots of
different objects, then the more the better. Budget neutron-server
using about 2GB of RAM in steady-state.

For rpc_workers, there needs to be enough to keep up with incoming
events from the various neutron agents. Signs that there are too few
can be agent heartbeats arriving late, nova vif bindings timing out
on the hypervisors, or rpc message timeout exceptions in agent logs
(for example, "broken pipe" errors).

There is also the rpc_state_report_workers option, which determines
the number fo RPC worker processes dedicated to process state reports
from the various agents. This may be increased to resolve frequent delay
in processing agents heartbeats.

.. note::
   If OVN ML2 plugin is used without any additional agents, neutron requires
   no worker for RPC message processing. Set both rpc_workers and
   rpc_state_report_workers to 0, to disable RPC workers.

.. note::
   ML2/OVN uses the ``[uwsgi]start-time = %t`` parameter to create the OVN hash
   ring registers during the initialization process. This value is populated
   by the uWSGi process with the start time. For more information, check
   `Configuring uWSGI <https://uwsgi-docs.readthedocs.io/en/latest/Configuration.html>`_.
