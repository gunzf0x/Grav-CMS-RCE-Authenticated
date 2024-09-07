# Grav CMS Remote Code Execution (Authenticated) - CVE-2024-28116

## Info

_This code is an adaptation from [`Grave` Github repository](https://github.com/akabe1/Graver) with some improvements based on [this video](https://ethicalhacking.uk/videos/CVE-2024-28116/)._

Exploit against `Grav CMS` (for versions below `1.7.45`) based on SSTI + RCE vulnerabilities, labeled as `CVE-2024-28116`. This script basically creates a page with the vulnerability, executes it and, finally, deletes the page after the execution.

## Usage
```shell-session
python3 Grav_CMS_RCE.py -t http://10.10.10.10 -u 'admin' -p 'S3cureP4ssw0rd' -x 'ping -c 1 10.10.10.9'
```

Help message:

```
$ python3 Grav_CMS_RCE.py -h

usage: Grav_CMS_RCE.py [-h] -t TARGET [-P PORT] -u USERNAME -p PASSWORD -x COMMAND [--no-delete-file] [--panel-route PANEL_ROUTE] [--no-banner] [--show-warnings]

Grav CMS RCE (Authenticated).

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        URL where Grav CMS is running. Example: http://10.10.10.10
  -P PORT, --port PORT  Port running Grav CMS. Default: 80
  -u USERNAME, --username USERNAME
                        Username to authenticate in Grav CMS
  -p PASSWORD, --password PASSWORD
                        Password for the user in Grav CMS.
  -x COMMAND, --command COMMAND
                        Command to inject/run.
  --no-delete-file      Do NOT delete the generated files. Useful to check command execution output.
  --panel-route PANEL_ROUTE
                        Admin Panel route in Grav CMS. Default: /admin
  --show-warnings       Show warnings (if there are).
```

If for some reason we do not want to delete the generated files, we can use `--no-delete-file` flag, visit the page the script indicates and read the command output.

## More info
More CVE-2024-28116/about this exploit info:
- Tested on `Grav CMS v1.7.44 - Admin 1.10.44`.
- [https://github.com/akabe1/Graver](https://github.com/akabe1/Graver)
- [https://nvd.nist.gov/vuln/detail/CVE-2024-28116](https://nvd.nist.gov/vuln/detail/CVE-2024-28116)
- [https://ethicalhacking.uk/videos/CVE-2024-28116/#gsc.tab=0](https://ethicalhacking.uk/videos/CVE-2024-28116/#gsc.tab=0)
- [https://github.com/getgrav/grav/security/advisories/GHSA-c9gp-64c4-2rrh](https://github.com/getgrav/grav/security/advisories/GHSA-c9gp-64c4-2rrh)

## Disclaimer
The owner of this repository is not responsible for the usage of this software. It was made for educational purposes only.

## Licence
- MIT
