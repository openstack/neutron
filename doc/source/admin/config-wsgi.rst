.. _config-wsgi:

Installing Neutron API via WSGI
===============================

This document is a guide to deploying neutron using WSGI. There are two ways to
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
to run behind uwsgi and mod_wsgi.

Neutron API behind uwsgi
------------------------

Create a ``/etc/neutron/neutron-api-uwsgi.ini`` file with the content below:

.. code-block:: ini

    [uwsgi]
    chmod-socket = 666
    socket = /var/run/uwsgi/neutron-api.socket
    lazy-apps = true
    add-header = Connection: close
    buffer-size = 65535
    hook-master-start = unix_signal:15 gracefully_kill_them_all
    thunder-lock = true
    plugins = python
    enable-threads = true
    worker-reload-mercy = 90
    exit-on-reload = false
    die-on-term = true
    master = true
    processes = 2
    wsgi-file = <path-to-neutron-bin-dir>/neutron-api

.. end

Start neutron-api:

.. code-block:: console

    # uwsgi --procname-prefix neutron-api --ini /etc/neutron/neutron-api-uwsgi.ini

.. end

Neutron API behind mod_wsgi
---------------------------

Create ``/etc/apache2/neutron.conf`` with content below:

.. code-block:: ini

    Listen 9696
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\" %D(us)" neutron_combined

    <Directory /usr/local/bin>
        Require all granted
    </Directory>

    <VirtualHost *:9696>
        WSGIDaemonProcess neutron-server processes=1 threads=1 user=stack display-name=%{GROUP}
        WSGIProcessGroup neutron-server
        WSGIScriptAlias / <path-to-neutron-bin-dir>/neutron-api
        WSGIApplicationGroup %{GLOBAL}
        WSGIPassAuthorization On
        ErrorLogFormat "%M"
        ErrorLog /var/log/neutron/neutron.log
        CustomLog /var/log/neutron/neutron_access.log neutron_combined
    </VirtualHost>

    Alias /networking <path-to-neutron-bin-dir>/neutron-api
    <Location /networking>
        SetHandler wsgi-script
        Options +ExecCGI
        WSGIProcessGroup neutron-server
        WSGIApplicationGroup %{GLOBAL}
        WSGIPassAuthorization On
    </Location>

    WSGISocketPrefix /var/run/apache2

.. end

For deb-based systems copy or symlink the file to ``/etc/apache2/sites-available``.
Then enable the neutron site:

.. code-block:: console

    # a2ensite neutron
    # systemctl reload apache2.service

.. end

For rpm-based systems copy the file to ``/etc/httpd/conf.d``. Then enable the
neutron site:

.. code-block:: console

    # systemctl reload httpd.service

.. end


Start Neutron RPC server
------------------------

When Neutron API is served by a web server (like Apache2) it is difficult
to start an rpc listener thread. So start the Neutron RPC server process to
serve this job:

.. code-block:: console

    # /usr/bin/neutron-rpc-server --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini

.. end

Neutron Worker Processes
------------------------

Neutron will attempt to spawn a number of child processes for handling API
and RPC requests. The number of API workers is set to the number of CPU
cores, further limited by available memory, and the number of RPC workers
is set to half that number.

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
