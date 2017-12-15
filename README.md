# ESMandADDeleteTool
McAfee ESM and Active Directory CleanUp tool

## Introduction
The main purpose of this tool is to delete Users that exist in ESM but not in Active Directory. A secondary function exists where an ESM account can be disabled, if it is disabled in Active Directory.

## Dependencies
Requires [ldap3](https://github.com/cannatag/ldap3) and [requests](https://github.com/requests/requests)

## Usage
To use this tool:
  run `python compareUsers.py`

You can also get to help by using -h switch:
```usage: compareUsers.py [-h] -a AD SERVER -d AD USERNAME [-n AD PASSWORD] -b AD
                       GROUP BASEDN -e ESM HOSTNAME -u ESM User
                       [-p ESM Password] -g ESM GROUP [-r | -s] [-o DIRECTORY]
                       [--write_ad_users] [--write_esm_users]
                       [--write_esmonly] [--write_all]

McAfee ESM and Active Directory Clean up Tool. The main purpose of this tool
is to delete Users that exist in ESM but not in Active Directory. A secondary
function exists where an ESM account can be disabled, if it is disabled in
Active Directory.

optional arguments:
  -h, --help            show this help message and exit
  -r, --delete          Delete Users that exist in ESM but not in Active Directory
  -s, --disable         Disable ESM Accounts that are disabled in Active Directory

AD options:
  -a AD SERVER, --ad_server AD SERVER
                        Active Directory Server Hostname/ip
  -d AD USERNAME, --ad_user AD USERNAME
                        DOMAIN\username for authentication
  -n AD PASSWORD, --ad_password AD PASSWORD
                        Domain User Password
  -b AD GROUP BASEDN, --ad_group AD GROUP BASEDN
                        AD Group Search Base DN, in a format similar to CN=Group,OU=Groups,DC=Example,DC=Com

SIEM Options:
  -e ESM HOSTNAME, --esm ESM HOSTNAME
                        ESM Hostname/ip
  -u ESM User, --esm_user ESM User
                        ESM Username for authentication
  -p ESM Password, --esm_password ESM Password
                        ESM User Password
  -g ESM GROUP, --esm_group ESM GROUP
                        ESM Group Name

Output options:
  -o DIRECTORY, --outdir DIRECTORY
                        Directory in which the dump will be saved (default: current)
  --write_ad_users      Create a spreadsheet containing only users in the AD Group
  --write_esm_users     Create a spreadsheet containing only users in the ESM Group
  --write_esmonly       Create a spreadsheet containing only users that exist in the ESM, but not in AD Group
  --write_all           Create a spreadsheet containing AD Users, ESM Users, and ESM Only Users
  ```
