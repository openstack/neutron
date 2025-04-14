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

.. _ci_jobs:

Neutron Jobs Running in Zuul CI
===============================

Tempest jobs running in Neutron CI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In upstream Neutron CI there are various tempest and neutron-tempest-plugin jobs
running.
Each of those jobs runs on slightly different configuration of Neutron services.
Below is a summary of those jobs.
::

    +----------------------------------------------+----------------------------------+-------+------------------+-------------+-----------------+----------+-------+--------+------------+-------------+
    | Job name                                     | Run tests                        | nodes | Operating system | L2 agent    | firewall        | L3 agent | L3 HA | L3 DVR | enable_dvr | Run in gate |
    |                                              |                                  |       |                  | driver      | mode            |          |       |        |            | queue       |
    +==============================================+==================================+=======+==================+==============+================+==========+=======+========+============+=============+
    |neutron-tempest-plugin-designate-scenario     |neutron_tempest_plugin.scenario.\ |   1   | Ubuntu Jammy     | openvswitch | openvswitch     | legacy   | False | False  | True       | No          |
    |                                              |test_dns_integration              |       |                  |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+-------+------------------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-plugin-linuxbridge            |neutron_tempest_plugin.api        |   1   | Ubuntu Jammy     | linuxbridge | iptables        | ha       | False | False  | False      | Yes         |
    |                                              |neutron_tempest_plugin.scenario   |       |                  |             |                 |          |       |        |            |             |
    |                                              |tempest.api.compute.servers.\     |       |                  |             |                 |          |       |        |            |             |
    |                                              |    test_attach_interfaces        |       |                  |             |                 |          |       |        |            |             |
    |                                              |tempest.api.compute.servers.\     |       |                  |             |                 |          |       |        |            |             |
    |                                              |    test_multiple_create          |       |                  |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+-------+------------------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-plugin-openvswitch            |neutron_tempest_plugin.api        |   1   | Ubuntu Jammy     | openvswitch | openvswitch     | ha       | False | False  | False      | Yes         |
    |                                              |neutron_tempest_plugin.scenario   |       |                  |             |                 |          |       |        |            |             |
    |                                              |tempest.api.compute.servers.\     |       |                  |             |                 |          |       |        |            |             |
    |                                              |    test_attach_interfaces        |       |                  |             |                 |          |       |        |            |             |
    |                                              |tempest.api.compute.servers.\     |       |                  |             |                 |          |       |        |            |             |
    |                                              |    test_multiple_create          |       |                  |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+-------+------------------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-plugin-openvswitch-\          |neutron_tempest_plugin.api        |   1   | Ubuntu Jammy     | openvswitch | iptables_hybrid | ha       | False | False  | False      | Yes         |
    |  iptables_hybrid                             |neutron_tempest_plugin.scenario   |       |                  |             |                 |          |       |        |            |             |
    |                                              |tempest.api.compute.servers.\     |       |                  |             |                 |          |       |        |            |             |
    |                                              |    test_attach_interfaces        |       |                  |             |                 |          |       |        |            |             |
    |                                              |tempest.api.compute.servers.\     |       |                  |             |                 |          |       |        |            |             |
    |                                              |    test_multiple_create          |       |                  |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+-------+------------------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-plugin-scenario-ovn           | neutron_tempest_plugin.scenario  |   1   | Ubuntu Jammy     | ovn         | ovn             | ---      | False | False  | False      | Yes         |
    |                                              |tempest.api.compute.servers.\     |       |                  |             |                 |          |       |        |            |             |
    |                                              |    test_attach_interfaces        |       |                  |             |                 |          |       |        |            |             |
    |                                              |tempest.api.compute.servers.\     |       |                  |             |                 |          |       |        |            |             |
    |                                              |    test_multiple_create          |       |                  |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+-------+------------------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-ovs-tempest-multinode-full            |tempest.api (without slow tests)  |   2   | Ubuntu Jammy     | openvswitch | openvswitch     | legacy   | False | False  | True       | Yes         |
    |                                              |tempest.scenario                  |       |                  |             |                 |          |       |        |            |             |
    |                                              |(only tests related to            |       |                  |             |                 |          |       |        |            |             |
    |                                              |Neutron and Nova)                 |       |                  |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+-------+------------------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-ovs-tempest-dvr-ha-multinode-full     |tempest.api (without slow tests)  |   3   | Ubuntu Jammy     | openvswitch | openvswitch     | dvr_snat | True  | True   | True       | No          |
    |(non-voting)                                  |tempest.scenario                  |       |                  |             |                 | dvr      |       |        |            |             |
    |                                              |                                  |       |                  |             |                 | dvr      |       |        |            |             |
    +----------------------------------------------+----------------------------------+-------+------------------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-ovs-tempest-slow                      |tempest slow tests                |   2   | Ubuntu Jammy     | openvswitch | openvswitch     | legacy   | False | False  | True       | Yes         |
    +----------------------------------------------+----------------------------------+-------+------------------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |tempest-integrated-networking                 |tempest.api (without slow tests)  |   1   | Ubuntu Jammy     | ovn         | ovn             | ---      | False | False  | True       | Yes         |
    |                                              |tempest.scenario                  |       |                  |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+-------+------------------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-ovn-tempest-ipv6-only-ovs-release     |tempest.api (without slow tests)  |   1   | Ubuntu Jammy     | ovn         | ovn             | ---      | False | False  | True       | Yes         |
    |                                              |(only tests related to            |       |                  |             |                 |          |       |        |            |             |
    |                                              |Neutron and Nova)                 |       |                  |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+-------+------------------+-------------+-----------------+----------+-------+--------+------------+-------------+

Grenade jobs running in Neutron CI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In upstream Neutron CI there are various Grenade jobs running.
Each of those jobs runs on slightly different configuration of Neutron services.
Below is summary of those jobs.
::

    +------------------------------------+-------+------------------+-------------+-------------+----------+-------+--------+------------+-------------+
    | Job name                           | nodes | Operating system | L2 agent    | firewall    | L3 agent | L3 HA | L3 DVR | enable_dvr | Run in gate |
    |                                    |       |                  |             | driver      | mode     |       |        |            | queue       |
    +====================================+=======+==================+=============+=============+==========+=======+========+============+=============+
    | neutron-ovs-grenade-multinode      |   2   | Ubuntu Jammy     | openvswitch | openvswitch | legacy   | False | False  | True       | Yes         |
    +------------------------------------+-------+------------------+-------------+-------------+----------+-------+--------+------------+-------------+
    | neutron-ovs-grenade-dvr-multinode  |   2   | Ubuntu Jammy     | openvswitch | openvswitch | dvr      | False | False  | True       | Yes         |
    |                                    |       |                  |             |             | dvr_snat |       |        |            |             |
    +------------------------------------+-------+------------------+-------------+-------------+----------+-------+--------+------------+-------------+

Tempest jobs running in Neutron experimental CI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In upstream Neutron CI there is also queue called ``experimental``. It includes
jobs which are not needed to be run on every patch and/or jobs which isn't
stable enough to be run always.
Those jobs can be run by making comment ``check experimental`` in the comment to
the patch in Gerrit.

Currently we have in that queue jobs like listed below.
::

    +----------------------------------------------+----------------------------------+-------+------------------+-------------+-----------------+----------+-------+--------+------------+-------------+
    | Job name                                     | Run tests                        | nodes | Operating system | L2 agent    | firewall        | L3 agent | L3 HA | L3 DVR | enable_dvr | Run in gate |
    |                                              |                                  |       |                  |             | driver          | mode     |       |        |            | queue       |
    +==============================================+==================================+=======+==================+=============+=================+==========+=======+========+============+=============+
    |neutron-ovn-tempest-with-uwsgi-loki           |tempest.api (without slow tests)  |   1   | Ubuntu Jammy     | ovn         | ovn             | ---      | ---   | ---    | ---        | No          |
    |(non-voting)                                  |tempest.scenario                  |       |                  |             |                 |          |       |        |            |             |
    |                                              |(only tests related to            |       |                  |             |                 |          |       |        |            |             |
    |                                              |Neutron and Nova)                 |       |                  |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+-------+------------------+-------------+-----------------+----------+-------+--------+------------+-------------+

And we also have Grenade jobs in the experimental queue.
::

    +--------------------------------+-------+------------------+-------------+-------------+----------+--------+------------+------------+-------------+
    | Job name                       | nodes | Operating system | L2 agent    | firewall    | L3 agent | L3 HA  | L3 DVR     | enable_dvr | Run in gate |
    |                                |       |                  |             | driver      | mode     |        |            |            | queue       |
    +================================+=======+=============+==================+=============+==========+========+============+============+=============+
    | neutron-ovn-grenade-multinode  |   2   | Ubuntu Jammy     | OVN         | ---         | ---      | ---    | ---        | False      | no          |
    | (non-voting)                   |       |                  |             |             |          |        |            |            |             |
    +--------------------------------+-------+------------------+-------------+-------------+----------+--------+------------+------------+-------------+

Columns description

* L2 agent - agent used on nodes in test job,
* firewall driver - driver configured in L2 agent's config,
* L3 agent mode - mode(s) configured for L3 agent(s) on test nodes,
* L3 HA - value of ``l3_ha`` option set in ``neutron.conf``,
* L3 DVR - value of ``router_distributed`` option set in ``neutron.conf``,
* enable_dvr - value of ``enable_dvr`` option set in ``neutron.conf``
