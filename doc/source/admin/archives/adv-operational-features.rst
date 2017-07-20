=============================
Advanced operational features
=============================

Logging settings
~~~~~~~~~~~~~~~~

Networking components use Python logging module to do logging. Logging
configuration can be provided in ``neutron.conf`` or as command-line
options. Command options override ones in ``neutron.conf``.

To configure logging for Networking components, use one of these
methods:

-  Provide logging settings in a logging configuration file.

   See `Python logging
   how-to <https://docs.python.org/howto/logging.html>`__ to learn more
   about logging.

-  Provide logging setting in ``neutron.conf``.

   .. code-block:: ini

      [DEFAULT]
      # Default log level is WARNING
      # Show debugging output in logs (sets DEBUG log level output)
      # debug = False

      # log_date_format = %Y-%m-%d %H:%M:%S

      # use_syslog = False
      # syslog_log_facility = LOG_USER

      # if use_syslog is False, we can set log_file and log_dir.
      # if use_syslog is False and we do not set log_file,
      # the log will be printed to stdout.
      # log_file =
      # log_dir =

Notifications
~~~~~~~~~~~~~

Notifications can be sent when Networking resources such as network,
subnet and port are created, updated or deleted.

Notification options
--------------------

To support DHCP agent, ``rpc_notifier`` driver must be set. To set up the
notification, edit notification options in ``neutron.conf``:

.. code-block:: ini

   # Driver or drivers to handle sending notifications. (multi
   # valued)
   # notification_driver=messagingv2

   # AMQP topic used for OpenStack notifications. (list value)
   # Deprecated group/name - [rpc_notifier2]/topics
   notification_topics = notifications

Setting cases
-------------

Logging and RPC
^^^^^^^^^^^^^^^

These options configure the Networking server to send notifications
through logging and RPC. The logging options are described in OpenStack
Configuration Reference . RPC notifications go to ``notifications.info``
queue bound to a topic exchange defined by ``control_exchange`` in
``neutron.conf``.

**Notification System Options**

A notification can be sent when a network, subnet, or port is created,
updated or deleted. The notification system options are:

* ``notification_driver``
    Defines the driver or drivers to handle the sending of a notification.
    The six available options are:

    * ``messaging``
        Send notifications using the 1.0 message format.
    * ``messagingv2``
        Send notifications using the 2.0 message format (with a message
        envelope).
    * ``routing``
        Configurable routing notifier (by priority or event_type).
    * ``log``
        Publish notifications using Python logging infrastructure.
    * ``test``
        Store notifications in memory for test verification.
    * ``noop``
        Disable sending notifications entirely.
* ``default_notification_level``
    Is used to form topic names or to set a logging level.
* ``default_publisher_id``
    Is a part of the notification payload.
* ``notification_topics``
    AMQP topic used for OpenStack notifications. They can be comma-separated
    values. The actual topic names will be the values of
    ``default_notification_level``.
* ``control_exchange``
    This is an option defined in oslo.messaging. It is the default exchange
    under which topics are scoped. May be overridden by an exchange name
    specified in the ``transport_url`` option. It is a string value.

Below is a sample ``neutron.conf`` configuration file:

.. code-block:: ini

    notification_driver = messagingv2

    default_notification_level = INFO

    host = myhost.com
    default_publisher_id = $host

    notification_topics = notifications

    control_exchange = openstack
