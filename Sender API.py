import argparse
import sys
import requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecurePlatformWarning)
urllib3.disable_warnings(urllib3.exceptions.SNIMissingWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    parser = argparse.ArgumentParser()
    parser.add_argument('--token', help='token, REQUIRED', required=True)
    parser.add_argument('--url', help='url, REQUIRED', required=True)
    parser.add_argument('--timeout', help='timeout', required=False)
    parser.add_argument('--verify', help='verify', required=False)
    parser.add_argument('--proxy_url', help='proxy_url', required=False)
    args, unknown = parser.parse_known_args()
    proxies = {'http': args.proxy_url, 'https': args.proxy_url} if args.proxy_url is not None else None
    timeout = 180 if args.timeout is None or args.timeout == '' or int(args.timeout) <= 0 else int(args.timeout)
    verify = True if args.verify == "true" else False
    endpoint = "{}/groups/".format(args.url.rstrip('/'))
    headers = {
        "Authorization": "Bearer {}".format(args.token),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    payload = {
        "title": "My Test Group"
    }
    session = requests.Session()
    response = session.post(endpoint, headers=headers, data=json.dumps(payload), verify=verify, timeout=timeout, proxies=proxies)
    response.raise_for_status()
    print(json.dumps(response.json()))
    exit(0)
except Exception as e:
    sys.stderr.write(str(e))
    exit(-1)
