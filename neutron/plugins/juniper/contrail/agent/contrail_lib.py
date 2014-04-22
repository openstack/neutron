import sys

import getopt
import logging
import socket
import thrift
import uuid

from nova_contrail_vif.gen_py.instance_service import InstanceService

from thrift.protocol import TBinaryProtocol
from thrift.transport import TTransport


def rpc_client_instance():
    """ Return an RPC client connection """
    import thrift.transport.TSocket as TSocket
    socket = TSocket.TSocket('127.0.0.1', 9090)
    try:
        transport = TTransport.TFramedTransport(socket)
        transport.open()
    except thrift.transport.TTransport.TTransportException:
        logging.error('Connection failure')
        return None
    protocol = TBinaryProtocol.TBinaryProtocol(transport)
    return InstanceService.Client(protocol)
# end rpc_client_instance


def uuid_from_string(idstr):
    """ Convert an uuid into an array of integers """
    if not idstr:
        return None
    hexstr = uuid.UUID(idstr).hex
    return [int(hexstr[i:i+2], 16) for i in range(32) if i % 2 == 0]
# end uuid_from_string
