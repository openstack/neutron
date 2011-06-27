import webob

from quantum.common.wsgi import Serializer


class Request(webob.Request):

    def best_match_content_type(self):
        return "application/json"

    def get_content_type(self):
        return "application/json"


def create_request(path, body):
    req = Request.blank(path)
    req.method = "POST"
    req.headers = {}
    req.headers['Accept'] = "application/json"
    req.body = body
    return req


def create_empty_request():
    return create_request("/v0.1/tenant.json", "")


def create_network_request(tenant_id, network_name):
    path = "/v0.1/tenants/%s/networks.json" % tenant_id
    data = {'network': {'network-name': '%s' % network_name}}
    content_type = "application/json"
    body = Serializer().serialize(data, content_type)
    return create_request(path, body)


def create_attachment_request(tid, nid, pid, attachment_id):
    path = "/v0.1/tenants/%s/networks/%s/ports/%s/attachment.json" % (tid,
      nid, pid)
    data = {'port': {'attachment-id': attachment_id}}
    content_type = "application/json"
    body = Serializer().serialize(data, content_type)
    return create_request(path, body)
