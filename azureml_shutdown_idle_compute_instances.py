# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

import json
import logging
import subprocess
import sys
import os.path
import time

from azureml.core import Workspace
from azureml.core.authentication import (AzureCliAuthentication,
                                         MsiAuthentication,
                                         ServicePrincipalAuthentication)
from azureml.core.compute import ComputeInstance
from configargparse import ArgParser

AUTH_CLI = 'azure-cli'
AUTH_MI = 'managed-identity'
AUTH_SP = 'service-principal'


def main():
    args = get_args()

    logging.basicConfig(
        format='%(asctime)s|%(process)d|%(levelname)s|%(module)s|%(funcName)s|%(message)s',
        level=args.verbosity,
    )

    logging.info("arguments:")
    logging.info(f'  subscription-id={args.subscription_id}')
    logging.info(f'  resource-group={args.resource_group}')
    logging.info(f'  workspace-name={args.workspace_name}')
    logging.info(f'  idle-threshold-sec={args.idle_threshold_sec}')
    logging.info(f'  interval-sec={args.interval_sec}')
    logging.info(f'  authentication={args.authentication}')
    logging.info(f'  tenant-id={args.tenant_id}')
    logging.info(f'  service-principal-id={args.service_principal_id}')
    logging.info(f'  verbosity={args.verbosity}')

    shutdown = AzureMLComputeInstanceShutdown(args)
    shutdown.run()

    return 0


class AzureMLComputeInstanceShutdown:
    def __init__(self, args):
        self.args = args
        self.workspace = self.open_azure_ml_workspace()

    def run(self):
        try:
            while True:
                logging.info("starting processing instances")
                self.process_compute_instances()
                logging.info("finished processing instances")
                if self.args.interval_sec == 0:
                    break
                time.sleep(self.args.interval_sec)
        except KeyboardInterrupt:
            logging.info("KeyboardInterrupt")

    def open_azure_ml_workspace(self):
        logging.info("connecting to workspace name:{0} subscription ID:{1}, resource group:{2}".format(
            self.args.workspace_name,
            self.args.subscription_id,
            self.args.resource_group,
        ))

        if self.args.authentication == AUTH_CLI:
            logging.info("using Azure CLI authentication")
            auth = AzureCliAuthentication()
        elif self.args.authentication == AUTH_MI:
            logging.info("using managed identity authentication")
            auth = MsiAuthentication()
        elif self.args.authentication == AUTH_SP:
            logging.info("using service principal authentication tenant ID:{0} service principal ID:{1}".format(
                self.args.tenant_id,
                self.args.service_principal_id,
            ))
            auth = ServicePrincipalAuthentication(
                tenant_id=self.args.tenant_id,
                service_principal_id=self.args.service_principal_id,
                service_principal_password=self.args.service_principal_password,
            )
        else:
            ex = Exception('Invalid authentication type.')
            logging.error(ex)
            raise ex

        workspace = Workspace(
            subscription_id=self.args.subscription_id,
            resource_group=self.args.resource_group,
            workspace_name=self.args.workspace_name,
            auth=auth,
        )

        return workspace

    def process_compute_instances(self):
        for compute_target in self.workspace.compute_targets.values():
            if compute_target.type == 'ComputeInstance':
                logging.info(
                    f'instance {compute_target.name} state {compute_target.status.state}')
                if compute_target.status.state == 'Running':
                    try:
                        logging.info(
                            f"processing compute instance {compute_target.name}")
                        if self.get_compute_target_info(compute_target)['idle'] == True:
                            logging.info(
                                f"stopping idle compute instance {compute_target.name}")
                            compute_target.stop(
                                wait_for_completion=False,
                                show_output=False,
                            )
                        else:
                            logging.info(
                                f"compute instance {compute_target.name} is not idle")
                    except Exception as ex:
                        logging.error(
                            f"failed to process compute instance {compute_target.name} with error {ex}"
                        )

    def get_compute_target_info(self, compute_target):
        ssh = SshClient(
            compute_target.admin_username,
            compute_target.public_ip_address,
            compute_target.ssh_port
        )

        SCRIPT = 'get_compute_instance_info.py'
        DIR = '/tmp'

        ssh.copy(
            f'scripts/{SCRIPT}',
            '/tmp',
        )

        result = ssh.exec(
            ['python3', os.path.join(DIR, SCRIPT), str(
                self.args.idle_threshold_sec)],
        )

        try:
            return json.loads(result)
        except json.JSONDecodeError:
            print('Failed to decode json result')
            print(f'Content: {result}')


class SshClient:
    def __init__(self, user, host, port=22):
        self.destination = f'{user}@{host}'
        self.port = str(port)

    def exec(self, command):
        result = exec(
            [
                'ssh',
                self.destination,
                '-p',
                self.port
            ] + command,
        )

        return result

    def copy(self, source, dest):
        exec(
            [
                'scp',
                '-P',
                self.port,
                source,
                f'{self.destination}:{dest}',
            ],
        )


def exec(command):
    ret = subprocess.run(command, stdout=subprocess.PIPE)

    if ret.returncode != 0:
        raise Exception(
            '{0} failed\n{1}\n{2}'.format(
                command,
                ret.stdout.decode('utf-8'),
                ret.stderr.decode('utf-8'),
            )
        )

    return ret.stdout.decode('utf-8')


def get_args():
    arg_parser = ArgParser(
        default_config_files=[
            './azureml_shutdown_idle_compute_instances.ini',
            './tmp/azureml_shutdown_idle_compute_instances.ini',
            '/config/*.ini',
        ]
    )
    arg_parser.add(
        '-s',
        '--subscription-id',
        required=True,
        help='ID of the Azure subscription containing the Azure ML workspace'
    )
    arg_parser.add(
        '-g',
        '--resource-group',
        required=True,
        help='Resource group containing the Azure ML workspace'
    )
    arg_parser.add(
        '-w',
        '--workspace-name',
        required=True,
        help='Name of the Azure ML workspace'
    )
    arg_parser.add(
        '-t',
        '--idle-threshold-sec',
        default=3600,
        type=int,
        help='Idle period in seconds for a compute instance to be considered idle (default 3600)'
    )
    arg_parser.add(
        '--interval-sec',
        default=0,
        type=int,
        help='Poll the status of compute instances every interval-sec seconds (default 0 = poll status once and exit)'
    )
    arg_parser.add(
        '-a', '--authentication',
        default=AUTH_MI,
        choices=[AUTH_CLI, AUTH_MI, AUTH_SP],
        help='Authentication method'
    )
    arg_parser.add('--tenant-id',
                   help='Tenant ID for service principal authentication')
    arg_parser.add('--service-principal-id',
                   help='Service principal ID for service principal authentication')
    arg_parser.add('--service-principal-password',
                   help='Service principal secret for service principal authentication')
    arg_parser.add(
        '-v', '--verbosity',
        default='INFO',
        choices=[
            'CRITICAL',
            'ERROR',
            'WARNING',
            'INFO',
            'DEBUG',
        ],
        help='Verbosity of script output'
    )
    arg_parser.add(
        '-c', '--config',
        is_config_file=True,
        help='Configuration file'
    )

    args = arg_parser.parse_args()

    if args.authentication == AUTH_SP and (
        not args.tenant_id
        or not args.service_principal_id
        or not args.service_principal_password
    ):
        print('Tenant ID, service principal ID and service principal password are required when using service-principal authentication.')
        arg_parser.print_help()
        sys.exit(1)

    return args


if __name__ == '__main__':
    sys.exit(main())
