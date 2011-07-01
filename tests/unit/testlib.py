import webob

from quantum.common.wsgi import Serializer


def create_request(path, body, content_type, method='GET'):
    req = webob.Request.blank(path)
    req.method = method
    req.headers = {}
    req.headers['Accept'] = content_type
    req.body = body
    return req


def create_network_list_request(tenant_id, format='xml'):
    method = 'GET'
    path = "/tenants/%(tenant_id)s/networks.%(format)s" % locals()
    content_type = "application/" + format
    return create_request(path, None, content_type, method)


def create_new_network_request(tenant_id, network_name, format='xml'):
    method = 'POST'
    path = "/tenants/%(tenant_id)s/networks.%(format)s" % locals()
    data = {'network': {'net-name': '%s' % network_name}}
    content_type = "application/" + format
    body = Serializer().serialize(data, content_type)
    return create_request(path, body, content_type, method)


def create_network_delete_request(tenant_id, network_id, format='xml'):
    method = 'DELETE'
    path = "/tenants/%(tenant_id)s/networks/" \
           "%(network_id)s.%(format)s" % locals()
    content_type = "application/" + format
    return create_request(path, None, content_type, method)


def create_port_list_request(tenant_id, network_id, format='xml'):
    method = 'GET'
    path = "/tenants/%(tenant_id)s/networks/" \
           "%(network_id)s/ports.%(format)s" % locals()
    content_type = "application/" + format
    return create_request(path, None, content_type, method)


def create_new_port_request(tenant_id, network_id, port_state, format='xml'):
    method = 'POST'
    path = "/tenants/%(tenant_id)s/networks/" \
           "%(network_id)s/ports.%(format)s" % locals()
    data = {'port': {'port-state': '%s' % port_state}}
    content_type = "application/" + format
    body = Serializer().serialize(data, content_type)
    return create_request(path, body, content_type, method)


def create_port_delete_request(tenant_id, network_id, port_id, format='xml'):
    method = 'DELETE'
    path = "/tenants/%(tenant_id)s/networks/" \
           "%(network_id)s/ports/%(port_id)s.%(format)s" % locals()
    content_type = "application/" + format
    return create_request(path, None, content_type, method)


def create_attachment_request(tid, nid, pid, attachment_id):
    path = "/v0.1/tenants/%s/networks/%s/ports/%s/attachment.json" % (tid,
      nid, pid)
    data = {'port': {'attachment-id': attachment_id}}
    content_type = "application/json"
    body = Serializer().serialize(data, content_type)
    return create_request(path, body)
