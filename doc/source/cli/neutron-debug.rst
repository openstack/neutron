.. This file is manually generated, unlike many of the other chapters.

=============
neutron-debug
=============

The :command:`neutron-debug` client is an extension to the :command:`neutron`
command-line interface (CLI) for the OpenStack neutron-debug tool.

This chapter documents :command:`neutron-debug` version ``2.3.0``.

For help on a specific :command:`neutron-debug` command, enter:

.. code-block:: console

   $ neutron-debug help COMMAND

.. _neutron-debug_usage:

neutron-debug usage
~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   usage: neutron-debug [--version] [-v] [-q] [-h] [-r NUM]
                        [--os-service-type <os-service-type>]
                        [--os-endpoint-type <os-endpoint-type>]
                        [--service-type <service-type>]
                        [--endpoint-type <endpoint-type>]
                        [--os-auth-strategy <auth-strategy>] [--os-cloud <cloud>]
                        [--os-auth-url <auth-url>]
                        [--os-tenant-name <auth-tenant-name> | --os-project-name <auth-project-name>]
                        [--os-tenant-id <auth-tenant-id> | --os-project-id <auth-project-id>]
                        [--os-username <auth-username>]
                        [--os-user-id <auth-user-id>]
                        [--os-user-domain-id <auth-user-domain-id>]
                        [--os-user-domain-name <auth-user-domain-name>]
                        [--os-project-domain-id <auth-project-domain-id>]
                        [--os-project-domain-name <auth-project-domain-name>]
                        [--os-cert <certificate>] [--os-cacert <ca-certificate>]
                        [--os-key <key>] [--os-password <auth-password>]
                        [--os-region-name <auth-region-name>]
                        [--os-token <token>] [--http-timeout <seconds>]
                        [--os-url <url>] [--insecure] [--config-file CONFIG_FILE]
                        <subcommand> ...

Subcommands
-----------

``probe-create``
  Create probe port - create port and interface within a network namespace.

``probe-list``
  List all probes.

``probe-clear``
  Clear all probes.

``probe-delete``
  Delete probe - delete port then delete the namespace.

``probe-exec``
  Execute commands in the namespace of the probe.

``ping-all``
  ``ping-all`` is an all-in-one command to ping all fixed IPs in a specified
  network.

.. _neutron-debug_optional:

neutron-debug optional arguments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``--version``
  Show program's version number and exit

``-v, --verbose, --debug``
  Increase verbosity of output and show tracebacks on
  errors. You can repeat this option.

``-q, --quiet``
  Suppress output except warnings and errors.

``-h, --help``
  Show this help message and exit

``-r NUM, --retries NUM``
  How many times the request to the Neutron server
  should be retried if it fails.

``--os-service-type <os-service-type>``
  Defaults to env[OS_NETWORK_SERVICE_TYPE] or network.

``--os-endpoint-type <os-endpoint-type>``
  Defaults to ``env[OS_ENDPOINT_TYPE]`` or public.

``--service-type <service-type>``
  DEPRECATED! Use --os-service-type.

``--endpoint-type <endpoint-type>``
  DEPRECATED! Use --os-endpoint-type.

``--os-auth-strategy <auth-strategy>``
  DEPRECATED! Only keystone is supported.

``os-cloud <cloud>``
  Defaults to env[OS_CLOUD].

``--os-auth-url <auth-url>``
  Authentication URL, defaults to env[OS_AUTH_URL].

``--os-tenant-name <auth-tenant-name>``
  Authentication tenant name, defaults to
  env[OS_TENANT_NAME].

``--os-project-name <auth-project-name>``
  Another way to specify tenant name. This option is
  mutually exclusive with --os-tenant-name. Defaults to
  env[OS_PROJECT_NAME].

``--os-tenant-id <auth-tenant-id>``
  Authentication tenant ID, defaults to
  env[OS_TENANT_ID].

``--os-project-id <auth-project-id>``
  Another way to specify tenant ID. This option is
  mutually exclusive with --os-tenant-id. Defaults to
  env[OS_PROJECT_ID].

``--os-username <auth-username>``
  Authentication username, defaults to env[OS_USERNAME].

``--os-user-id <auth-user-id>``
  Authentication user ID (Env: OS_USER_ID)

``--os-user-domain-id <auth-user-domain-id>``
  OpenStack user domain ID. Defaults to
  env[OS_USER_DOMAIN_ID].

``--os-user-domain-name <auth-user-domain-name>``
  OpenStack user domain name. Defaults to
  env[OS_USER_DOMAIN_NAME].

``--os-project-domain-id <auth-project-domain-id>``
  Defaults to env[OS_PROJECT_DOMAIN_ID].

``--os-project-domain-name <auth-project-domain-name>``
  Defaults to env[OS_PROJECT_DOMAIN_NAME].

``--os-cert <certificate>``
  Path of certificate file to use in SSL connection.
  This file can optionally be prepended with the private
  key. Defaults to env[OS_CERT].

``--os-cacert <ca-certificate>``
  Specify a CA bundle file to use in verifying a TLS
  (https) server certificate. Defaults to
  env[OS_CACERT].

``--os-key <key>``
  Path of client key to use in SSL connection. This
  option is not necessary if your key is prepended to
  your certificate file. Defaults to env[OS_KEY].

``--os-password <auth-password>``
  Authentication password, defaults to env[OS_PASSWORD].

``--os-region-name <auth-region-name>``
  Authentication region name, defaults to
  env[OS_REGION_NAME].

``--os-token <token>``
  Authentication token, defaults to env[OS_TOKEN].

``--http-timeout <seconds>``
  Timeout in seconds to wait for an HTTP response.
  Defaults to env[OS_NETWORK_TIMEOUT] or None if not
  specified.

``--os-url <url>``
  Defaults to env[OS_URL]

``--insecure``
  Explicitly allow neutronclient to perform "insecure"
  SSL (https) requests. The server's certificate will
  not be verified against any certificate authorities.
  This option should be used with caution.

``--config-file CONFIG_FILE``
  Config file for interface driver (You may also use l3_agent.ini)

neutron-debug probe-create command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   usage: neutron-debug probe-create NET

Create probe port - create port and interface,
then place it into the created network namespace.

Positional arguments
--------------------

``NET ID``
  ID of the network in which the probe will be created.

neutron-debug probe-list command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   usage: neutron-debug probe-list

List probes.

neutron-debug probe-clear command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   usage: neutron-debug probe-clear

Clear all probes.

neutron-debug probe-delete command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   usage: neutron-debug probe-delete <port-id>

Remove a probe.

Positional arguments
--------------------

``<port-id>``
  ID of the probe to delete.

neutron-debug probe-exec command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   usage: neutron-debug probe-exec <port-id> <command>

Execute commands in the namespace of the probe

neutron-debug ping-all command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   usage: neutron-debug ping-all <port-id> --timeout <number>

All-in-one command to ping all fixed IPs in a specified network.
A probe creation is not needed for this command.
A new probe is created automatically.
It will, however, need to be deleted manually when it is no longer needed.
When there are multiple networks, the newly created probe will be attached
to a random network and thus the ping will take place from within that
random network.

Positional arguments
--------------------

``<port-id>``
  ID of the port to use.

Optional arguments
------------------

``--timeout <timeout in seconds>``
  Optional ping timeout.

neutron-debug example
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

   usage: neutron-debug create-probe <NET_ID>

Create a probe namespace within the network identified by ``NET_ID``.
The namespace will have the name of qprobe-<UUID of the probe port>

.. note::

   For the following examples to function, the security group rules
   may need to be modified to allow the SSH (TCP port 22) or ping
   (ICMP) traffic into network.

.. code-block:: console

   usage: neutron-debug probe-exec <probe ID> "ssh <IP of instance>"

SSH to an instance within the network.

.. code-block:: console

   usage: neutron-debug ping-all <network ID>

Ping all instances on this network to verify they are responding.

.. code-block:: console

   usage: neutron-debug probe-exec <probe_ID> dhcping <VM_MAC address> -s <IP of DHCP server>

Ping the DHCP server for this network using dhcping to verify it is working.
