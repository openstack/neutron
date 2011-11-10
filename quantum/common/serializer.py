from xml.dom import minidom
import webob.exc

from quantum.common import utils


class Serializer(object):
    """Serializes and deserializes dictionaries to certain MIME types."""

    def __init__(self, metadata=None, default_xmlns=None):
        """Create a serializer based on the given WSGI environment.

        'metadata' is an optional dict mapping MIME types to information
        needed to serialize a dictionary to that type.

        """
        self.metadata = metadata or {}
        self.default_xmlns = default_xmlns

    def _get_serialize_handler(self, content_type):
        handlers = {
            'application/json': self._to_json,
            'application/xml': self._to_xml,
        }

        try:
            return handlers[content_type]
        except Exception:
            raise exception.InvalidContentType(content_type=content_type)

    def serialize(self, data, content_type):
        """Serialize a dictionary into the specified content type."""
        return self._get_serialize_handler(content_type)(data)

    def deserialize(self, datastring, content_type):
        """Deserialize a string to a dictionary.

        The string must be in the format of a supported MIME type.

        """
        try:
            return self.get_deserialize_handler(content_type)(datastring)
        except Exception:
            raise webob.exc.HTTPBadRequest("Could not deserialize data")

    def get_deserialize_handler(self, content_type):
        handlers = {
            'application/json': self._from_json,
            'application/xml': self._from_xml,
        }

        try:
            return handlers[content_type]
        except Exception:
            raise exception.InvalidContentType(content_type=content_type)

    def _from_json(self, datastring):
        return utils.loads(datastring)

    def _from_xml(self, datastring):
        xmldata = self.metadata.get('application/xml', {})
        plurals = set(xmldata.get('plurals', {}))
        node = minidom.parseString(datastring).childNodes[0]
        return {node.nodeName: self._from_xml_node(node, plurals)}

    def _from_xml_node(self, node, listnames):
        """Convert a minidom node to a simple Python type.

        listnames is a collection of names of XML nodes whose subnodes should
        be considered list items.

        """
        if len(node.childNodes) == 1 and node.childNodes[0].nodeType == 3:
            return node.childNodes[0].nodeValue
        elif node.nodeName in listnames:
            return [self._from_xml_node(n, listnames)
                    for n in node.childNodes if n.nodeType != node.TEXT_NODE]
        else:
            result = dict()
            for attr in node.attributes.keys():
                result[attr] = node.attributes[attr].nodeValue
            for child in node.childNodes:
                if child.nodeType != node.TEXT_NODE:
                    result[child.nodeName] = self._from_xml_node(child,
                                                                 listnames)
            return result

    def _to_json(self, data):
        return utils.dumps(data)

    def _to_xml(self, data):
        metadata = self.metadata.get('application/xml', {})
        # We expect data to contain a single key which is the XML root.
        root_key = data.keys()[0]
        doc = minidom.Document()
        node = self._to_xml_node(doc, metadata, root_key, data[root_key])

        xmlns = node.getAttribute('xmlns')
        if not xmlns and self.default_xmlns:
            node.setAttribute('xmlns', self.default_xmlns)

        return node.toprettyxml(indent='', newl='')

    def _to_xml_node(self, doc, metadata, nodename, data):
        """Recursive method to convert data members to XML nodes."""
        result = doc.createElement(nodename)

        # Set the xml namespace if one is specified
        # TODO(justinsb): We could also use prefixes on the keys
        xmlns = metadata.get('xmlns', None)
        if xmlns:
            result.setAttribute('xmlns', xmlns)
        if type(data) is list:
            collections = metadata.get('list_collections', {})
            if nodename in collections:
                metadata = collections[nodename]
                for item in data:
                    node = doc.createElement(metadata['item_name'])
                    node.setAttribute(metadata['item_key'], str(item))
                    result.appendChild(node)
                return result
            singular = metadata.get('plurals', {}).get(nodename, None)
            if singular is None:
                if nodename.endswith('s'):
                    singular = nodename[:-1]
                else:
                    singular = 'item'
            for item in data:
                node = self._to_xml_node(doc, metadata, singular, item)
                result.appendChild(node)
        elif type(data) is dict:
            collections = metadata.get('dict_collections', {})
            if nodename in collections:
                metadata = collections[nodename]
                for k, v in data.items():
                    node = doc.createElement(metadata['item_name'])
                    node.setAttribute(metadata['item_key'], str(k))
                    text = doc.createTextNode(str(v))
                    node.appendChild(text)
                    result.appendChild(node)
                return result
            attrs = metadata.get('attributes', {}).get(nodename, {})
            for k, v in data.items():
                if k in attrs:
                    result.setAttribute(k, str(v))
                else:
                    node = self._to_xml_node(doc, metadata, k, v)
                    result.appendChild(node)
        else:
            # Type is atom.
            node = doc.createTextNode(str(data))
            result.appendChild(node)
        return result
