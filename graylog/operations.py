""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, json
from connectors.core.connector import ConnectorError, get_logger

logger = get_logger('graylog')

errors = {
    '401': 'Unauthorized, API key invalid',
    '405': 'Method Not Allowed, Method other than POST used',
    '413': 'Request Entity Too Large, Sample file size over max limit',
    '415': 'Unsupported Media Type',
    '418': 'Unsupported File Type Sample, file type is not supported',
    '419': 'Request quota exceeded',
    '420': 'Insufficient arguments',
    '421': 'Invalid arguments',
    '500': 'Internal error',
    '502': 'Bad Gateway',
    '513': 'File upload failed'
}

sort_dict = {
    'True': 'asc',
    'False': 'desc'
}


class Graylog(object):
    def __init__(self, config, *args, **kwargs):
        self.username = config.get('username')
        self.password = config.get('password')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/api/'.format(url)
        else:
            self.url = url + '/api/'
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, url, method, data=None, params=None):
        try:
            url = self.url + url
            headers = {
                'X-Requested-By': 'fortisoar',
                'Accept': 'application/json'
            }
            logger.debug("Endpoint {0}".format(url))
            response = requests.request(method, url, data=data, params=params, auth=(self.username, self.password),
                                        headers=headers,
                                        verify=self.verify_ssl)
            logger.debug("response_content {0}:{1}".format(response.status_code, response.content))
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            elif response.status_code == 404:
                return response
            else:
                logger.error("{0}".format(errors.get(response.status_code, '')))
                raise ConnectorError("{0}".format(errors.get(response.status_code, response.text)))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value:
            updated_payload[key] = value
    return updated_payload


def get_clusters(config, params):
    gl = Graylog(config)
    endpoint = 'clusters'
    try:
        response = gl.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_cluster_node_jvm(config, params):
    gl = Graylog(config)
    endpoint = 'cluster/{0}/jvm'.format(params.get('node_id'))
    try:
        response = gl.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_cluster_input_states(config, params):
    gl = Graylog(config)
    endpoint = 'cluster/inputstates'
    try:
        response = gl.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_cluster_processing_status(config, params):
    gl = Graylog(config)
    endpoint = '/cluster/processing/status'
    try:
        response = gl.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_indexer_cluster_health(config, params):
    gl = Graylog(config)
    endpoint = '/system/indexer/cluster/health'
    try:
        response = gl.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def search_relative(config, params):
    gl = Graylog(config)
    endpoint = '/search/universal/relative'
    fields = params.get('fields')
    if not isinstance(fields, list):
        fields = fields.split(",")
    try:
        payload = {
            'query': params.get('query'),
            'range': params.get('time_range'),
            'limit': params.get('limit'),
            'offset': params.get('offset'),
            'filter': params.get('filter'),
            'fields': fields,
            'sort': sort_dict.get(params.get('sort')),
            'decorate': params.get('decorate')
        }
        payload = check_payload(payload)
        response = gl.make_rest_call(endpoint, 'POST', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def search_absolute(config, params):
    gl = Graylog(config)
    endpoint = '/search/universal/absolute'
    fields = params.get('fields')
    if not isinstance(fields, list):
        fields = fields.split(",")
    try:
        payload = {
            'query': params.get('query'),
            'from': params.get('start_time'),
            'to': params.get('end_time'),
            'limit': params.get('limit'),
            'offset': params.get('offset'),
            'filter': params.get('filter'),
            'fields': fields,
            'sort': sort_dict.get(params.get('sort')),
            'decorate': params.get('decorate')
        }
        payload = check_payload(payload)
        response = gl.make_rest_call(endpoint, 'POST', params=payload)
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def search_events(config, params):
    gl = Graylog(config)
    endpoint = 'events/search'
    try:
        payload = {'query': params.get('query'),
                   'filter': params.get('filter'),
                   'page': params.get('offset'),
                   'sort_direction': sort_dict.get(params.get('sort')),
                   'per_page': params.get('limit'),
                   'timerange': {
                       'type': 'relative',
                       'range': params.get('time_range')
                   }
                   }
        payload = check_payload(payload)
        response = gl.make_rest_call(endpoint, 'POST', data=json.dumps(payload))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def _check_health(config):
    try:
        response = get_clusters(config, params={})
        if response:
            return True
    except Exception as err:
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'get_clusters': get_clusters,
    'get_cluster_node_jvm': get_cluster_node_jvm,
    'get_cluster_input_states': get_cluster_input_states,
    'get_cluster_processing_status': get_cluster_processing_status,
    'get_indexer_cluster_health': get_indexer_cluster_health,
    'search_relative': search_relative,
    'search_absolute': search_absolute,
    'search_events': search_events
}
