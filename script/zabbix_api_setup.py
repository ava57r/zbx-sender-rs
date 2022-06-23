#!/usr/bin/env python3

import argparse
import json
import os
import time
from sys import exit
import urllib.request as rq
from urllib.parse import urljoin


ZABBIX_USER = os.environ.get('ZBX_USER', "Admin")
ZABBIX_PASSWORD = os.environ.get('ZBX_PASSWORD', "zabbix")
ZABBIX_HOSTGROUP = os.environ.get('ZBX_TEST_HOSTGROUP', "Test hosts")
ZABBIX_HOST_NAME = os.environ.get('ZBX_TEST_HOST_NAME', "Test host")
ZABBIX_ITEM_NAME_PREFIX = os.environ.get('ZBX_TEST_ITEM_NAME_PREFIX', "Test")
ZABBIX_ITEM_KEY_PREFIX = os.environ.get('ZBX_TEST_ITEM_KEY_PREFIX', "test")


class ZabbixError(Exception):
    # code: int
    # message: str
    # data: str
    # raw: dict[str, Any]

    def __init__(self, response):
        if 'error' not in response:
            raise RuntimeError('ZabbixError constructed from a non-error response')

        message = response['error']['message']
        data = response['error']['data']
        super().__init__(f"{message} {data}")

        self.code = response['error']['code']
        self.message = message
        self.data = data
        self.raw = response


class Zabbix:
    # endpoint: str
    # request_id: int
    # token: Optional[str]

    def __init__(self, endpoint):
        self.endpoint = urljoin(endpoint, 'api_jsonrpc.php')
        self.request_id = 1
        self.token = None

    def login(self, username, password):
        self.token = self.call('user.login', {'user': username, 'password': password})

    def call(self, method, params):
        operation = {
            'jsonrpc': '2.0',
            'id': f"{self.request_id}",
            'method': method,
            'params': params
        }
        self.request_id += 1

        if self.token is not None:
            operation['auth'] = self.token

        data = json.dumps(operation).encode('utf-8')

        request = rq.Request(
            self.endpoint,
            data,
            headers={'Content-Type': 'application/json'}
        )

        with rq.urlopen(request) as response:
            if response.status != 200:
                raise RuntimeError(f"Request failed with status: {response.status}")

            result = json.load(response)
            if 'error' in result:
                raise ZabbixError(result)

            return result['result']


def get_first_itemid(result, identifier):
    return result[f"{identifier}s"][0]


def call_with_status(zabbix: Zabbix, message, *args, identifier=None):
    print(f"{message}... ", end='')
    result = zabbix.call(*args)
    print('success.', end='')

    if identifier is not None:
        result = get_first_itemid(result, identifier)
        print(f" ({identifier}={result})", end='')

    print('')  # Newline
    return result


def wait_for_api(zabbix, timeout, report_interval=10):
    timeout = timeout * pow(10, 9)
    elapsed = 0
    start_time = time.monotonic_ns()
    while True:
        try:
            zabbix.call('apiinfo.version', [])
            break
        except Exception as e:
            current_time = time.monotonic_ns()
            elapsed = current_time - start_time + pow(10, 9)
            if elapsed < timeout:
                if (elapsed // pow(10, 9)) % report_interval == 0:
                    print(
                        f"Waiting for API ("
                        f"{elapsed // pow(10, 9)}s elapsed;"
                        f" {(timeout - elapsed) // pow(10, 9)}s remaining"
                        ")..."
                    )
                time.sleep(1)
                continue
            raise e


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
            '--wait',
            type=int,
            help="Wait up to this many seconds for Zabbix to be available",
            metavar="SECONDS"
    )
    parser.add_argument(
        '--allow-ips',
        help="Allowed IPs (hostname, IPs, or CIDRs) for Zabbix Trapper items",
        default='127.0.0.1, ::1'
    )
    parser.add_argument(
        '--tls-psk-identity',
        help="Allowed TLS PSK identity string for the test host"
    )
    parser.add_argument(
        '--tls-psk-key',
        help="TLS PSK (pre-shared key) for the test host"
    )
    parser.add_argument(
        '--tls-accept',
        help="Which TLS modes should the server accept",
        choices=['unencrypted', 'psk', 'cert'],
        action='append'
    )
    parser.add_argument('zabbix_url')
    args = parser.parse_args()

    if 'psk' in args.tls_accept:
        if (args.tls_psk_identity is None) or (args.tls_psk_key is None):
            parser.error("--psk-identity and --psk-key must both"
                         " be specified when using --tls-accept psk")
        if len(args.tls_psk_key) < 32:
            parser.error("--psk-key must be at least 32 hex digits")
    else:
        if args.tls_psk_identity is not None or args.tls_psk_key is not None:
            parser.error("--psk-identity and --psk-key can only"
                         " be specified when using --tls-accept psk")

    zabbix = Zabbix(args.zabbix_url)
    try:
        if args.wait is not None:
            wait_for_api(zabbix, args.wait)

        zabbix.login(ZABBIX_USER, ZABBIX_PASSWORD)

        group_id = call_with_status(
            zabbix,
            f"Creating Host Group \"{ZABBIX_HOSTGROUP}\"",
            'hostgroup.create', {'name': ZABBIX_HOSTGROUP},
            identifier='groupid'
        )
        host = {
            'host': ZABBIX_HOST_NAME,
            'groups': [{'groupid': group_id}]
        }
        mode_values = {
            'unencrypted': 1,
            'psk': 2,
            'cert': 4
        }

        if args.tls_accept is None:
            args.tls_accept = ['unencrypted']
        tls_accept_value = 0
        for mode in args.tls_accept:
            tls_accept_value += mode_values[mode]
        host.update(tls_accept=tls_accept_value)

        if (
            'psk' in args.tls_accept
            and args.tls_psk_identity is not None
            and args.tls_psk_key is not None
        ):
            host.update({
                'tls_psk_identity': args.tls_psk_identity,
                'tls_psk': args.tls_psk_key
            })

        host_id = call_with_status(
            zabbix,
            f"Creating Host \"{ZABBIX_HOST_NAME}\"",
            'host.create', host,
            identifier='hostid'
        )

        item_valuetypes = {'float': 0, 'character': 1, 'unsigned': 3, 'text': 4}

        for item_valuetype, item_valuetype_id in item_valuetypes.items():
            item_name = f"{ZABBIX_ITEM_NAME_PREFIX} - {item_valuetype}"
            item_key = f"{ZABBIX_ITEM_KEY_PREFIX}.{item_valuetype}"
            call_with_status(
                zabbix,
                f"Creating Item \"{item_name}\"",
                'item.create', {
                    'hostid': host_id,
                    'name': item_name,
                    'key_': item_key,
                    'type': 2,  # Zabbix trapper
                    'value_type': item_valuetype_id,
                    'trapper_hosts': args.allow_ips,  # IPv4/6 all hosts
                },
                identifier='itemid'
            )

    except ZabbixError as e:
        print(f"FAILED!\nError: {e}\n\nResponse:\n\n{e.raw}")
        exit(1)


if __name__ == '__main__':
    main()
