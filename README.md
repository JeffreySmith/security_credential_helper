# security_credential_helper

## About

**security_credential_helper** is a command-line tool and Python library for securely storing and managing credentials using [Hadoop](https://github.com/apache/hadoop)'s `CredentialProvider` and Java KeyStore (JCEKS) files.  
It is compatible with both standalone environments and [Apache Ambari](https://ambari.apache.org/) managed clusters.

---

## Features

- Create, update, retrieve, and delete credentials in a JCEKS file
- Supports both password-protected and passwordless JCEKS files
- Works as a CLI tool and as a Python library
- Integrates with Ambari agent (if available) for secure operations
- Can run credential management commands as another user (if permissions allow)
- Extensible to support future storage backends (e.g. HDFS)

---

## Installation

Clone this repo and run:
```sh
pip2 install .
```

**Dependencies:**  
- Python 2.7 (with [`typing`](https://pypi.org/project/typing/), [`pathlib2`](https://pypi.org/project/pathlib2/), and [`enum34`](https://pypi.org/project/enum34/))
- Java (required for Hadoop credential operations)
- `hadoop` command must be available in `$PATH`

---

## Usage

### As a CLI Tool

```sh
security_credential_helper --file jceks://file/path/to/your.jceks --alias myalias
```

#### Common CLI Options

- `--file`/`-f`: Path to your JCEKS file (`jceks://file/...`)
- `--alias`/`-a`: The alias to save or retrieve
- `--password`/`-p`: The password to store
- `--get-all`/`-g`: List all aliases in the JCEKS file
- `--delete`/`-d`: Delete an alias from the JCEKS file
- `--update`/`-u`: Update an existing password/alias
- `--delete_jceks`/`-x`: Delete the JCEKS file and its .crc
- `--user`: Run commands as a specific user (if permissions allow)
- `--tests`/`-t`: Run an end-to-end credential test
- `--quiet`/`-q`: Suppress error output

#### Example: Add a password

```sh
security_credential_helper --file jceks://file/home/my_user/creds.jceks --alias db.password
```

#### Example: Retrieve a password

```sh
security_credential_helper --file jceks://file/etc/credentials/creds.jceks --alias db.password
```

#### Example: List all aliases

```sh
security_credential_helper --file jceks://file/home/my_user/creds.jceks --get-all
```

---

### As a Python Library

```python
from security_credential_helper import (
    extract_password, save_password, get_aliases,
    delete_password, update_password, test_jceks, delete_jceks_file
)

# Save a password
err = save_password("jceks://file/home/hadoop/creds.jceks", "db.password", user="user_to_run_as")
if err:
    print("Error:", err)

# Retrieve a password
pw, err = extract_password("jceks://file/home/hadoop/creds.jceks", "db.password")
if err:
    print("Error:", err)
else:
    print("Password:", pw)
```

---

## Design Notes

- **Ambari Integration:** If the tool is running under Ambari, it uses Ambari's resource_management libraries for security and privilege management.
- **Pluggable Storage:** Currently supports only local files (`jceks://file/...`), but is structured to allow HDFS and other storage backends in the future.
- **Error Handling:** Errors are logged and reported; most commands will exit with a non-zero status on failure.

---

## License

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

---

## Disclaimer

This tool is not an official [Hadoop](https://github.com/apache/hadoop) or [Ambari](https://github.com/apache/ambari) project, but is designed for compatibility with their credential management systems.

