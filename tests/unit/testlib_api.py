import webob

from quantum.common.wsgi import Serializer


def create_request(path, body, content_type, method='GET'):
    req = webob.Request.blank(path)
    req.method = method
    req.headers = {}
    req.headers['Accept'] = content_type
    req.body = body
    return req


def network_list_request(tenant_id, format='xml'):
    method = 'GET'
    path = "/tenants/%(tenant_id)s/networks.%(format)s" % locals()
    content_type = "application/%s" % format
    return create_request(path, None, content_type, method)


def show_network_request(tenant_id, network_id, format='xml'):
    method = 'GET'
    path = "/tenants/%(tenant_id)s/networks" \
           "/%(network_id)s.%(format)s" % locals()
    content_type = "application/%s" % format
    return create_request(path, None, content_type, method)


def new_network_request(tenant_id, network_name='new_name',
                        format='xml', custom_req_body=None):
    method = 'POST'
    path = "/tenants/%(tenant_id)s/networks.%(format)s" % locals()
    data = custom_req_body or {'network': {'net-name': '%s' % network_name}}
    content_type = "application/%s" % format
    body = Serializer().serialize(data, content_type)
    return create_request(path, body, content_type, method)


def update_network_request(tenant_id, network_id, network_name, format='xml',
                           custom_req_body=None):
    method = 'PUT'
    path = "/tenants/%(tenant_id)s/networks" \
           "/%(network_id)s.%(format)s" % locals()
    data = custom_req_body or {'network': {'net-name': '%s' % network_name}}
    content_type = "application/%s" % format
    body = Serializer().serialize(data, content_type)
    return create_request(path, body, content_type, method)


def network_delete_request(tenant_id, network_id, format='xml'):
    method = 'DELETE'
    path = "/tenants/%(tenant_id)s/networks/" \
           "%(network_id)s.%(format)s" % locals()
    content_type = "application/%s" % format
    return create_request(path, None, content_type, method)


def port_list_request(tenant_id, network_id, format='xml'):
    method = 'GET'
    path = "/tenants/%(tenant_id)s/networks/" \
           "%(network_id)s/ports.%(format)s" % locals()
    content_type = "application/%s" % format
    return create_request(path, None, content_type, method)


def show_port_request(tenant_id, network_id, port_id, format='xml'):
    method = 'GET'
    path = "/tenants/%(tenant_id)s/networks/%(network_id)s" \
           "/ports/%(port_id)s.%(format)s" % locals()
    content_type = "application/%s" % format
    return create_request(path, None, content_type, method)


def new_port_request(tenant_id, network_id, port_state,
                     format='xml', custom_req_body=None):
    method = 'POST'
    path = "/tenants/%(tenant_id)s/networks/" \
           "%(network_id)s/ports.%(format)s" % locals()
    data = custom_req_body or port_state and \
           {'port': {'port-state': '%s' % port_state}}
    content_type = "application/%s" % format
    body = data and Serializer().serialize(data, content_type)
    return create_request(path, body, content_type, method)


def port_delete_request(tenant_id, network_id, port_id, format='xml'):
    method = 'DELETE'
    path = "/tenants/%(tenant_id)s/networks/" \
           "%(network_id)s/ports/%(port_id)s.%(format)s" % locals()
    content_type = "application/%s" % format
    return create_request(path, None, content_type, method)


def update_port_request(tenant_id, network_id, port_id, port_state,
                        format='xml', custom_req_body=None):
    method = 'PUT'
    path = "/tenants/%(tenant_id)s/networks" \
           "/%(network_id)s/ports/%(port_id)s.%(format)s" % locals()
    data = custom_req_body or {'port': {'port-state': '%s' % port_state}}
    content_type = "application/%s" % format
    body = Serializer().serialize(data, content_type)
    return create_request(path, body, content_type, method)


def get_attachment_request(tenant_id, network_id, port_id, format='xml'):
    method = 'GET'
    path = "/tenants/%(tenant_id)s/networks/" \
           "%(network_id)s/ports/%(port_id)s/attachment.%(format)s" % locals()
    content_type = "application/%s" % format
    return create_request(path, None, content_type, method)


def put_attachment_request(tenant_id, network_id, port_id,
                              attachment_id, format='xml'):
    method = 'PUT'
    path = "/tenants/%(tenant_id)s/networks/" \
           "%(network_id)s/ports/%(port_id)s/attachment.%(format)s" % locals()
    data = {'port': {'attachment-id': attachment_id}}
    content_type = "application/%s" % format
    body = Serializer().serialize(data, content_type)
    return create_request(path, body, content_type, method)


def delete_attachment_request(tenant_id, network_id, port_id,
                              attachment_id, format='xml'):
    method = 'DELETE'
    path = "/tenants/%(tenant_id)s/networks/" \
           "%(network_id)s/ports/%(port_id)s/attachment.%(format)s" % locals()
    content_type = "application/%s" % format
    return create_request(path, None, content_type, method)
