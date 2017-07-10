Block storage node (Optional)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you want to deploy the Block Storage service, configure one
additional storage node.

Configure network interfaces
----------------------------

* Configure the management interface:

  * IP address: ``10.0.0.41``

  * Network mask: ``255.255.255.0`` (or ``/24``)

  * Default gateway: ``10.0.0.1``

Configure name resolution
-------------------------

#. Set the hostname of the node to ``block1``.

#. .. include:: shared/edit_hosts_file.txt

#. Reboot the system to activate the changes.
