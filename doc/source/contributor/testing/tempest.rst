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

.. _tempest_testing:

Tempest Testing
===============

Tempest basics in Networking projects
-------------------------------------
Tempest is the integration test suite of Openstack, for details see
`Tempest Testing Project <https://docs.openstack.org/tempest/latest/>`_.

Tempest makes it possible to add project-specific plugins, and for networking
this is `neutron-tempest-plugin <https://opendev.org/openstack/neutron-tempest-plugin>`_.

neutron-tempest-plugin covers API and scenario tests not just for core Neutron
functionality, but for stadium projects as well.
For reference please read `Testing Neutron\'s related sections <testing.html#api-tests>`_

API Tests
~~~~~~~~~

API tests (neutron-tempest-plugin/neutron_tempest_plugin/api/) are
intended to ensure the function
and stability of the Neutron API. As much as possible, changes to
this path should not be made at the same time as changes to the code
to limit the potential for introducing backwards-incompatible changes,
although the same patch that introduces a new API should include an API
test.

Since API tests target a deployed Neutron daemon that is not test-managed,
they should not depend on controlling the runtime configuration
of the target daemon. API tests should be black-box - no assumptions should
be made about implementation. Only the contract defined by Neutron's REST API
should be validated, and all interaction with the daemon should be via
a REST client.

The neutron-tempest-plugin/neutron_tempest_plugin directory was copied from the
Tempest project around the Kilo timeframe. At the time, there was an overlap of tests
between the Tempest and Neutron repositories. This overlap was then eliminated by carving
out a subset of resources that belong to Tempest, with the rest in Neutron.

API tests that belong to Tempest deal with a subset of Neutron's resources:

* Port
* Network
* Subnet
* Security Group
* Router
* Floating IP

These resources were chosen for their ubiquity. They are found in most
Neutron deployments regardless of plugin, and are directly involved in the
networking and security of an instance. Together, they form the bare minimum
needed by Neutron.

This is excluding extensions to these resources (For example: Extra DHCP
options to subnets, or snat_gateway mode to routers) that are not mandatory
in the majority of cases.

Tests for other resources should be contributed to the neutron-tempest-plugin
repository. Scenario tests should be similarly split up between Tempest and
Neutron according to the API they're targeting.

To create an API test, the testing class must at least inherit from
neutron_tempest_plugin.api.base.BaseNetworkTest base class. As some of tests
may require certain extensions to be enabled, the base class provides
``required_extensions`` class attribute which can be used by subclasses to
define a list of required extensions for a particular test class.

Scenario Tests
~~~~~~~~~~~~~~

Scenario tests (neutron-tempest-plugin/neutron_tempest_plugin/scenario), like API tests,
use the Tempest test infrastructure and have the same requirements. Guidelines for
writing a good scenario test may be found at the Tempest developer guide:
https://docs.openstack.org/tempest/latest/field_guide/scenario.html

Scenario tests, like API tests, are split between the Tempest and Neutron
repositories according to the Neutron API the test is targeting.

Some scenario tests require advanced ``Glance`` images (for example, ``Ubuntu``
or ``CentOS``) in order to pass. Those tests are skipped by default. To enable
them, include the following in ``tempest.conf``:

.. code-block:: ini

   [compute]
   image_ref = <uuid of advanced image>
   [neutron_plugin_options]
   default_image_is_advanced = True

To use the ``advanced image`` only for the tests that really need it and
``cirros`` for the rest to keep test execution as fast as possible:

.. code-block:: ini

   [compute]
   image_ref = <uuid of cirros image>
   [neutron_plugin_options]
   advanced_image_ref = <uuid of advanced image>
   advanced_image_flavor_ref = <suitable flavor for the advance image>
   advanced_image_ssh_user = <username for the advanced image>

Specific test requirements for advanced images are:

#. ``test_trunk`` requires ``802.11q`` kernel module loaded.
#. ``test_metadata`` requires capabilty to run ``curl`` for IPv6 addresses.
#. ``test_multicast`` needs to execute python script on the VM to open
   multicast sockets.
#. ``test_mtu`` requires ping to be able to send packets with specific ``mtu``.

Zuul basics & job structure
---------------------------
Zuul is the gating system behind Openstack, for details see:
`Zuul - A Project Gating System <https://zuul-ci.org/docs/zuul/>`_.

Zuul job definitions are in yaml, ansible in the depths. The job definitions can be
inherited. Networking projects job definitions parents are coming from
`devstack zuul job config <https://opendev.org/openstack/devstack/src/branch/master/.zuul.yaml>`_
and from `tempest <https://opendev.org/openstack/tempest/src/branch/master/tempest>`_
and defined in `neutron-tempest-plugin zuul.d folder <https://opendev.org/openstack/neutron-tempest-plugin/src/branch/master/zuul.d>`_
and in `neutron zuul.d folder <https://opendev.org/openstack/neutron/src/branch/master/zuul.d>`_ .

Where to look
-------------

Debugging zuul results
~~~~~~~~~~~~~~~~~~~~~~
Tempest executed with different configurations,
for details check this page
:ref:`Tempest jobs running in Neutron CI<ci_jobs>`

When zuul reports back job results to a review it gives links to the results
as well.

The logs can be checked online if you select ``Logs`` tab on the logs page.

* ``job-output.txt`` is the full log which contains not just test execution
  logs, but devstack console output.
* ``test_results.html`` is the clickable html test report.
* ``controller`` and ``compute`` (in case of multinode job) are a dictionary
  tree containing the relevant files (configuration files, logs etc)
  created in the job. For example under controller/logs/etc/neutron/ you can
  check how Neutron services were configured, or in the file
  controller/logs/tempest_conf.txt you can check tempest configuration file.
* services' log files are the in files ``controller/logs/screen-`*`.txt``,
  so for example neutron l2 agent logs are in the file
  controller/logs/screen-q-agt.txt.

Downloading logs
++++++++++++++++
There is a possibility to download all logs related to a job.

If you choose this on the zuul logs page select ``Artifacts`` tab on the
logs page and click on ``Download all logs``. This will download a script
``download-logs.sh``, which when executed downloads all the logs for the job
under ``/tmp/``:

.. code-block:: shell

    $ chmod +x download-logs.sh
    $ ./download-logs.sh
    2020-12-07T18:12:09+01:00 | Querying https://zuul.opendev.org/api/tenant/openstack/build/8caed05f5ba441b4be2b061d1d421e4e for manifest
    2020-12-07T18:12:11+01:00 | Saving logs to /tmp/zuul-logs.c8ZhLM
    2020-12-07T18:12:11+01:00 | Getting logs from https://3612101d6c142bf9c77a-c96c299047b55dcdeaefef8e344ceab6.ssl.cf1.rackcdn.com/694539/11/check/tempest-slow-py3/8caed05/
    2020-12-07T18:12:11+01:00 |   compute1/logs/apache/access_log.txt                                              [ 0001/0337 ]
    ...

    $ ls /tmp/zuul-logs.c8ZhLM/
    compute1
    controller

Executing tempest locally
~~~~~~~~~~~~~~~~~~~~~~~~~
For executing tempest locally you need a working devstack, to make it worse
if you have to debug a test executed in a multinode job you need a multinode
setup as well.

For devstack documentation please refer to this page:
`DevStack <https://docs.openstack.org/devstack/latest/>`_

To have tempest installed and have a proper configuration file for it in your
local.conf file enable tempest as service:

.. code-block:: ini

    ENABLED_SERVICES+=tempest

or

.. code-block:: ini

    enable_service tempest

To use specific config options for tempest you can add those as well to
local.conf:

.. code-block:: ini

    [[test-config|/opt/stack/tempest/etc/tempest.conf]]
    [network-feature-enabled]
    qos_placement_physnet=physnet1

To make devstack setup neutron and neutron-tempest-plugin as well enable their
devstack plugin:

.. code-block:: ini

    enable_plugin neutron https://opendev.org/openstack/neutron
    enable_plugin neutron-tempest-plugin https://opendev.org/openstack/neutron-tempest-plugin

If you need a special image for the tests you can set that too in local.conf:

.. code-block:: ini

    IMAGE_URLS="http://download.cirros-cloud.net/0.3.4/cirros-0.3.4-i386-disk.img,https://cloud-images.ubuntu.com/releases/bionic/release/ubuntu-18.04-server-cloudimg-amd64.img"
    ADVANCED_IMAGE_NAME=ubuntu-18.04-server-cloudimg-amd64
    ADVANCED_INSTANCE_TYPE=ds512M
    ADVANCED_INSTANCE_USER=ubuntu

If devstack succeeds you can find tempest and neutron-tempest-plugin under
``/opt/stack/`` directory (with all other project folders which are set to be
installed from git).

Tempest's configuration file is under ``/opt/stack/tempest/etc/`` folder, you
can check there if everything is as expected.

You can check if neutron-tempest-plugin is known as a tempest plugin by
tempest:

.. code-block:: shell

    $ tempest list-plugins
    +---------------------------------+------------------------------------------------------------+
    |               Name              |                         EntryPoint                         |
    +---------------------------------+------------------------------------------------------------+
    |          neutron_tests          |     neutron_tempest_plugin.plugin:NeutronTempestPlugin     |
    +---------------------------------+------------------------------------------------------------+

To execute a given test or group of tests you can use a regex, or you can use
the idempotent id of a test or the tag associated with the test:

.. code-block:: shell

    tempest run --config etc/tempest.conf --regex tempest.scenario
    tempest run --config etc/tempest.conf --regex neutron_tempest_plugin.scenario
    tempest run --config etc/tempest.conf smoke
    tempest run --config etc/tempest.conf ab40fc48-ca8d-41a0-b2a3-f6679c847bfe
