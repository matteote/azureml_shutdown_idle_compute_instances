# Sample script to shutdown idle Azure ML compute instances
This script polls all running compute instances of an Azure ML workspace.

If an instance is idle for more than a predefined period of time, the script shuts it down.
## Requirements
### OS
Tested on Ubuntu 18.04 (other Ubuntu versions or Linux distributions may work)
### Packages
- libssl-dev
- python3
- python3-pip
- rustc

### Python packages
- azure-cli-core
- azureml-core
- configargparse

### SSH configuration of Azure ML compute instances
Provision an SSH keypair for the Linux user that will run the script.

It is recommended to store the key safely, e.g. in Azure Key Vault.

When deploying a new Azure ML compute instance:
- Enable SSH
- Enter the SSH public key of the Linux user that will run the script.

### Authentication
#### Managed Identity
- The script must be executed on Azure VM running Ubuntu 18.04.
- Assign a managed identity to the VM.
- Assign the Contributor role in Azure ML to the managed identity of the VM.
- Set `authentication` to `managed-identity` (default, optional).
#### Service Principal
- Create a new service principal.
- Generate a new secret for the service principal.
- Assign the Contributor role in Azure ML to the service principal.
- Set `authentication` to `service-principal`.
- Pass tenant ID, service principal ID and service principal secret (`service-principal-password`) to the script.
#### Azure CLI
- Install Azure CLI
- Login to Azure CLI with an account that has the Contributor role in Azure ML
- Set `authentication` to `azure-cli`.

## Installation
1. Clone the repository to a local folder.
1. Install the required APT packages.
   
   `sudo apt install -y libssl-dev python3 python3-pip rustc`

1. Install the required Python packages.

    `pip3 install -r requirements.txt`

## Usage
`python3 azureml_shutdown_idle_compute_instances.py [<options>]`

### Configuration
The script can be configured using any of the following methods:
- configuration files
- command line options
- environment variables

#### Configuration files
A configuration file can be specified with the `--config` option.

The script additionally looks for configuration files in some predefined locations:
- `./azureml_shutdown_idle_compute_instances.ini`
- `./tmp/azureml_shutdown_idle_compute_instances.ini`
- `/config/*.ini`

Configuration files follow the _ini_ format.

Example:

```ini
subscription-id=aabbccdd-eeff-0011-2233-445566778899
resource-group=rg-azureml
workspace-name=azureml-workspace
authentication=service-principal
tenant-id=aabbccdd-eeff-0011-2233-445566778899
service-principal-id=aabbccdd-eeff-0011-2233-445566778899
service-principal-password=**********************************
```

#### Options

| Parameter                      | File parameter               | Environment Variable       | Description                                                                                   |           Required           | Default value    | Valid values                                                                        |
| ------------------------------ | ---------------------------- | -------------------------- | --------------------------------------------------------------------------------------------- | :--------------------------: | ---------------- | ----------------------------------------------------------------------------------- |
| `-h --help`                    |                              |                            | Display command line help                                                                     |
| `-s --subscription-id`         | `subscription-id`            | SUBSCRIPTION_ID            | ID of the Azure subscription containing the Azure ML workspace                                |             Yes              |
| `-g --resource-group`          | `resource-group`             | RESOURCE_GROUP             | Resource group containing the Azure ML workspace                                              |             Yes              |
| `-w --workspace-name`          | `workspace-name`             | WORKSPACE_NAME             | Name of the Azure ML workspace                                                                |             Yes              |
| `-t --idle-threshold-sec`      | `idle-threshold-sec`         | IDLE_THRESHOLD_SEC         | Idle period in seconds for a compute instance to be considered idle                           |                              | 3600             |
| `--interval-sec`               | `interval-sec`               | INTERVAL_SEC               | Poll the status of compute instances every interval-sec seconds (0=poll status once and exit) |                              | 0                |
| `-a --authentication`          | `authentication`             | AUTHENTICATION             | Authentication method                                                                         |                              | managed-identity | <ul><li>azure-cli</li><li>managed-identity</li><li>service-principal</li></ul>      |
| `--tenant-id`                  | `tenant-id`                  | TENANT_ID                  | Tenant ID for service principal authentication                                                | if auth is service-principal |
| `--service-principal-id`       | `service-principal-id`       | SERVICE_PRINCIPAL_ID       | Service principal ID for service principal authentication                                     | if auth is service-principal |
| `--service-principal-password` | `service-principal-password` | SERVICE_PRINCIPAL_PASSWORD | Service principal secret for service principal authentication                                 | if auth is service-principal |
| `-v --verbosity`               | `verbosity`                  | VERBOSITY                  | Verbosity of script output                                                                    |                              | INFO             | <ul><li>CRITICAL</li><li>ERROR</li><li>WARNING</li><li>INFO</li><li>DEBUG</li></ul> |
| `-c --config`                  |                              | CONFIG                     | Configuration file                                                                            |

