# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import http.client
import json
import sys
from datetime import datetime


def main(argv):
    if len(argv) != 2 or not argv[1].isdigit():
        print('Usage {0} <idle_threshold_in_sec>'.format(argv[0]))
        sys.exit(1)

    idle_threshold_in_sec = int(argv[1])

    try:
        collector = Collector(idle_threshold_in_sec)
        print(collector.get_info())
    except Exception as ex:
        print('Failed to collect instance information: {}'.format(ex))
        return 2

    return 0


class Collector:
    def __init__(self, idle_threshold_in_sec):
        self.idle_threshold_in_sec = idle_threshold_in_sec

    def get_info(self):
        uptime = self.get_instance_uptime()
        notebooks = self.get_notebooks()

        result = {
            'timestamp': datetime.now().isoformat(),
            'uptime': uptime,
            'notebooks': notebooks,
        }

        if self.are_all_notebooks_idle(notebooks) \
                and uptime > self.idle_threshold_in_sec:
            result['idle'] = True
        else:
            result['idle'] = False

        return json.dumps(result)

    def get_instance_uptime(self):
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        return uptime_seconds

    def get_notebooks(self):
        try:
            conn = http.client.HTTPConnection('localhost:8888')
            conn.request('GET', '/api/sessions')
            response = conn.getresponse()
        except Exception as ex:
            raise Exception('Failed retrieving Jupyter sessions') from ex

        if response.status != 200:
            raise Exception(
                'Failed retrieving Jupyter sessions: HTTP status {}'.format(response.status))

        try:
            content = response.read().decode('utf-8')
        except UnicodeError as ex:
            raise Exception('Failed decoding Jupyter sessions') from ex

        try:
            return [
                {
                    "path":             notebook['path'],
                    "execution_state":  notebook['kernel']['execution_state'],
                    "connections":      notebook['kernel']['connections'],
                    "last_activity":    notebook['kernel']['last_activity'],
                }
                for notebook in json.loads(content)
            ]
        except:
            return []

    def are_all_notebooks_idle(self, notebooks):
        for n in notebooks:
            if (n['execution_state'] != 'idle' or
                n['connections'] > 0 or
                    self.was_notebook_recently_updated(n)):
                return False
        return True

    def was_notebook_recently_updated(self, notebook):
        last_activity = datetime.strptime(
            notebook['last_activity'], "%Y-%m-%dT%H:%M:%S.%fz")
        return (datetime.now() - last_activity).total_seconds() < self.idle_threshold_in_sec


if __name__ == '__main__':
    sys.exit(main(sys.argv))
