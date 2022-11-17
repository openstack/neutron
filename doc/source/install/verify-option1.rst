Networking Option 1: Provider networks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* List agents to verify successful launch of the neutron agents:

  .. code-block:: console

     $ openstack network agent list

     +--------------------------------------+--------------------+------------+-------------------+-------+-------+---------------------------+
     | ID                                   | Agent Type         | Host       | Availability Zone | Alive | State | Binary                    |
     +--------------------------------------+--------------------+------------+-------------------+-------+-------+---------------------------+
     | 0400c2f6-4d3b-44bc-89fa-99093432f3bf | Metadata agent     | controller | None              | True  | UP    | neutron-metadata-agent    |
     | 83cf853d-a2f2-450a-99d7-e9c6fc08f4c3 | DHCP agent         | controller | nova              | True  | UP    | neutron-dhcp-agent        |
     | ec302e51-6101-43cf-9f19-88a78613cbee | Open vSwitch agent | compute    | None              | True  | UP    | neutron-openvswitch-agent |
     | fcb9bc6e-22b1-43bc-9054-272dd517d025 | Open vSwitch agent | controller | None              | True  | UP    | neutron-openvswitch-agent |
     +--------------------------------------+--------------------+------------+-------------------+-------+-------+---------------------------+

  .. end

  The output should indicate three agents on the controller node and one
  agent on each compute node.
