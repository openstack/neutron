Networking Option 2: Self-service networks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* List agents to verify successful launch of the neutron agents:

  .. code-block:: console

     $ openstack network agent list

     +--------------------------------------+--------------------+------------+-------------------+-------+-------+---------------------------+
     | ID                                   | Agent Type         | Host       | Availability Zone | Alive | State | Binary                    |
     +--------------------------------------+--------------------+------------+-------------------+-------+-------+---------------------------+
     | f49a4b81-afd6-4b3d-b923-66c8f0517099 | Metadata agent     | controller | None              | True  | UP    | neutron-metadata-agent    |
     | 27eee952-a748-467b-bf71-941e89846a92 | Open vSwitch agent | controller | None              | True  | UP    | neutron-openvswitch-agent |
     | 08905043-5010-4b87-bba5-aedb1956e27a | Open vSwitch agent | compute1   | None              | True  | UP    | neutron-openvswitch-agent |
     | 830344ff-dc36-4956-84f4-067af667a0dc | L3 agent           | controller | nova              | True  | UP    | neutron-l3-agent          |
     | dd3644c9-1a3a-435a-9282-eb306b4b0391 | DHCP agent         | controller | nova              | True  | UP    | neutron-dhcp-agent        |
     +--------------------------------------+--------------------+------------+-------------------+-------+-------+---------------------------+

  .. end

  The output should indicate four agents on the controller node and one
  agent on each compute node.
