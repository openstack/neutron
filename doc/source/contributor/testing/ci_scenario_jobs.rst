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


Neutron jobs running in Zuul CI
===============================

Tempest jobs running in Neutron CI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In upstream Neutron CI there are various tempest and neutron-tempest-plugin jobs
running.
Each of those jobs runs on slightly different configuration of Neutron services.
Below is a summary of those jobs.
::

    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    | Job name                                     | Run tests                        | python  | nodes | L2 agent    | firewall        | L3 agent | L3 HA | L3 DVR | enable_dvr | Run in gate |
    |                                              |                                  | version |       |             | driver          | mode     |       |        |            | queue       |
    +==============================================+==================================+=========+=======+=============+=================+==========+=======+========+============+=============+
    |neutron-tempest-plugin-api                    |neutron_tempest_plugin.api        |   3.6   |   1   | openvswitch | openvswitch     | legacy   | False | False  | True       | Yes         |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-plugin-designate-scenario     |neutron_tempest_plugin.scenario.\ |   3.6   |   1   | openvswitch | openvswitch     | legacy   | False | False  | True       | No          |
    |                                              |test_dns_integration              |         |       |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-plugin-dvr-multinode-scenario |neutron_tempest_plugin.scenario   |   3.6   |   2   | openvswitch | openvswitch     | dvr_snat | False | True   | True       | No          |
    |(non-voting)                                  |                                  |         |       |             |                 | dvr_snat |       |        |            |             |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-plugin-scenario-linuxbridge   |neutron_tempest_plugin.scenario   |   3.6   |   1   | linuxbridge | iptables        | legacy   | False | False  | False      | Yes         |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-plugin-scenario-openvswitch   |neutron_tempest_plugin.scenario   |   3.6   |   1   | openvswitch | openvswitch     | legacy   | False | False  | False      | Yes         |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-plugin-scenario-openvswitch-\ |neutron_tempest_plugin.scenario   |   3.6   |   1   | openvswitch | iptables_hybrid | legacy   | False | False  | False      | Yes         |
    |  iptables_hybrid                             |                                  |         |       |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |tempest-integrated-networking                 |tempest.api (without slow tests)  |   3.6   |   1   | openvswitch | openvswitch     | legacy   | False | False  | True       | Yes         |
    |                                              |tempest.scenario                  |         |       |             |                 |          |       |        |            |             |
    |                                              |(only tests related to            |         |       |             |                 |          |       |        |            |             |
    |                                              |Neutron and Nova)                 |         |       |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-dvr                           |tempest.api (without slow tests)  |   3.6   |   1   | openvswitch | openvswitch     | dvr_snat | False | True   | True       | Yes         |
    |                                              |tempest.scenario                  |         |       |             |                 |          |       |        |            |             |
    |                                              |(only tests related to            |         |       |             |                 |          |       |        |            |             |
    |                                              |Neutron and Nova)                 |         |       |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-linuxbridge                   |tempest.api (without slow tests)  |   3.6   |   1   | linuxbridge | iptables        | legacy   | False | False  | True       | Yes         |
    |                                              |tempest.scenario                  |         |       |             |                 |          |       |        |            |             |
    |                                              |(only tests related to            |         |       |             |                 |          |       |        |            |             |
    |                                              |Neutron and Nova)                 |         |       |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |tempest-multinode-full-py3                    |tempest.api (without slow tests)  |   3.6   |   2   | openvswitch | openvswitch     | legacy   | False | False  | True       | No          |
    |(non-voting)                                  |tempest.scenario                  |         |       |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-dvr-ha-multinode-full         |tempest.api (without slow tests)  |   3.6   |   3   | openvswitch | openvswitch     | dvr      | True  | True   | True       | No          |
    |(non-voting)                                  |tempest.scenario                  |         |       |             |                 | dvr_snat |       |        |            |             |
    |                                              |                                  |         |       |             |                 | dvr_snat |       |        |            |             |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-iptables_hybrid               |tempest.api (without slow tests)  |   3.6   |   1   | openvswitch | iptables_hybrid | legacy   | False | False  | True       | Yes         |
    |                                              |tempest.scenario                  |         |       |             |                 |          |       |        |            |             |
    |                                              |(only tests related to            |         |       |             |                 |          |       |        |            |             |
    |                                              |Neutron and Nova)                 |         |       |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |tempest-slow-py3                              |tempest slow tests                |   3.6   |   2   | openvswitch | openvswitch     | legacy   | False | False  | True       | Yes         |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |neutron-tempest-with-uwsgi                    |tempest.api (without slow tests)  |   3.6   |   1   | openvswitch | openvswitch     | legacy   | False | False  | True       | No          |
    |(non-voting)                                  |tempest.scenario                  |         |       |             |                 |          |       |        |            |             |
    |                                              |(only tests related to            |         |       |             |                 |          |       |        |            |             |
    |                                              |Neutron and Nova)                 |         |       |             |                 |          |       |        |            |             |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+
    |tempest-ipv6-only                             |tempest smoke + IPv6 tests        |   3.6   |   1   | openvswitch | openvswitch     | legacy   | False | False  | True       | Yes         |
    +----------------------------------------------+----------------------------------+---------+-------+-------------+-----------------+----------+-------+--------+------------+-------------+

Grenade jobs running in Neutron CI
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In upstream Neutron CI there are various Grenade jobs running.
Each of those jobs runs on slightly different configuration of Neutron services.
Below is summary of those jobs.
::

    +--------------------------------+---------+-------+-------------+-------------+----------+-------+--------+------------+-------------+
    | Job name                       | python  | nodes | L2 agent    | firewall    | L3 agent | L3 HA | L3 DVR | enable_dvr | Run in gate |
    |                                | version |       |             | driver      | mode     |       |        |            | queue       |
    +================================+=========+=======+=============+=============+==========+=======+========+============+=============+
    | neutron-grenade                |   2.7   |   1   | openvswitch | openvswitch | legacy   | False | False  | True       | Yes         |
    +--------------------------------+---------+-------+-------------+-------------+----------+-------+--------+------------+-------------+
    | grenade-py3                    |   3.6   |   1   | openvswitch | openvswitch | legacy   | False | False  | True       | Yes         |
    +--------------------------------+---------+-------+-------------+-------------+----------+-------+--------+------------+-------------+
    | neutron-grenade-multinode      |   3.6   |   2   | openvswitch | openvswitch | legacy   | False | False  | True       | Yes         |
    +--------------------------------+---------+-------+-------------+-------------+----------+-------+--------+------------+-------------+
    | neutron-grenade-dvr-multinode  |   3.6   |   2   | openvswitch | openvswitch | dvr      | False | False  | True       | Yes         |
    |                                |         |       |             |             | dvr_snat |       |        |            |             |
    +--------------------------------+---------+-------+-------------+-------------+----------+-------+--------+------------+-------------+

Columns description

* L2 agent - agent used on nodes in test job,
* firewall driver - driver configured in L2 agent's config,
* L3 agent mode - mode(s) configured for L3 agent(s) on test nodes,
* L3 HA - value of ``l3_ha`` option set in ``neutron.conf``,
* L3 DVR - value of ``router_distributed`` option set in ``neutron.conf``,
* enable_dvr - value of ``enable_dvr`` option set in ``neutron.conf``
