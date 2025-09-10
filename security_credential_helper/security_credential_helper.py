#!/usr/bin/env python2
"""Extract, save, and delete passwords from jceks files, whether they are password protected or not."""
from __future__ import print_function

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from collections import Callable # pylint: disable=unused-import
from enum import Enum
from urlparse import ParseResult, urlparse # pylint: disable=unused-import
from typing import Optional, List, Union, Tuple # pylint: disable=unused-import
import argparse
import errno
import glob
import itertools
import os
import pwd
import subprocess
import sys
import re
import pathlib2 as pathlib

running_from_ambari = True

try:
    from resource_management.core import shell
    from resource_management.core.shell import as_user
    from resource_management.core import sudo
    from resource_management.core.logger import Logger
except ImportError:
    running_from_ambari = False
    import logging
    logging.basicConfig(level=logging.ERROR,)
    Logger = logging.getLogger("security_credential_helper")


# We're only going to use this if Ambari is enabled
# This mimics the used fields from the output of subprocess.run
class CommandResults(object):
    def __init__(self, returncode, stdout, stderr):
        # type: (int, str, str) -> None
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    def __repr__(self):
        return ("CommandResults(returncode={0!r}, stdout={1!r}, stderr={2!r})"
                .format(self.returncode, self.stdout, self.stderr))
# This will later make it easier to enable saving/retrieving passwords form either the local
# filesystem or HDFS in the future.
class Netloc(Enum):
    HDFS = "HDFS"
    FILE = "FILE"
    @classmethod
    def from_str(cls, value):
        if isinstance(value, str):
            value = value.upper()
            if value in dir(cls):
                return cls[value]
        raise ValueError("{} is not a valid Netloc".format(value))

def log_error(error):
    # type: (Union[str, None]) -> None
    if not error:
        return
    if running_from_ambari:
        error = "{}: {}".format(os.path.basename(__file__), error)
    Logger.error(error)

def _create_folder(netloc, path):
    # type: (Union[Netloc, None], pathlib.PosixPath) -> bool
    if netloc is None:
        return False
    path = path.absolute()
    ambari_path = str(path)
    result = False
    if netloc == Netloc.FILE:
        if running_from_ambari:
            if sudo.path_exists(ambari_path) and sudo.path_isdir(ambari_path):
                result = True
            elif not sudo.path_exists(ambari_path):
                sudo.makedir(ambari_path, 0o777)
                # Because of umask, we have to explicitly set the permissions
                sudo.chmod(ambari_path, 0o777)
                result = True
            elif sudo.path_isfile(ambari_path):
                log_error("Path '{}' exists and is not a directory".format(path))

        else:
            if not path.exists():
                try:
                    path.mkdir()
                    # Because of umask, we have to explicitly set the permissions
                    path.chmod(0o777)
                    result = True
                except OSError as e:
                    if e.errno == errno.EACCES:
                        log_error("Permission denied while trying to create directory '{}'".format(path))
                    elif e.errno == errno.ENOENT:
                        log_error("Parent directory of '{}' does not exist".format(path))

            elif path.exists() and not path.is_dir():
                log_error("Path '{}' exists and is not a directory".format(path))
            elif path.exists() and path.is_dir():
                result = True
    elif netloc == Netloc.HDFS:
        log_error("Creating a folder in HDFS is not yet implemented")

    return result

def _run_command(command, user):
    #type: (List[str], Union[str, None]) -> CommandResults
    if user and user.strip() != "":
        try:
            pwd.getpwnam(user)
        except KeyError:
            error_message = "User '{}' does not exist. Please provide a valid user.".format(user)
            return CommandResults(-2, "", error_message)
    else:
        user = None
    try:
        if running_from_ambari:
            out = run_command_ambari(command, user)
        else:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=run_as_user(user),
                env=os.environ
            )
            stdout, stderr = process.communicate()
            out = CommandResults(process.returncode, stdout.decode("utf-8"), stderr.decode("utf-8"))
        return out
    except Exception as e: # pylint: disable=broad-except
        log_error("Error while running command: {}".format(e))
        return CommandResults(-1, "", str(e))

def run_command_ambari(command, user=None):
    # type: (List[str], Union[str, None]) -> CommandResults
    if not user:
        user = pwd.getpwuid(os.getuid()).pw_name
    user_command = as_user(command, env=os.environ, user=user)
    returncode, stdout, stderr = shell.call(user_command, stderr=subprocess.PIPE, quiet=True)
    result = CommandResults(returncode, stdout, stderr) # type: CommandResults
    return result

def run_as_user(user=None):
    # type: (Union[str, None]) -> Callable[[], None]
    def result():
        if user:
            try:
                pw_record = pwd.getpwnam(user) # type: pwd.struct_passwd
                os.setgid(pw_record.pw_gid)
                os.setuid(pw_record.pw_uid)
            except OSError as e:
                log_error("Error setting user: {}".format(e))
    return result

def get_uri_info(uri):
    # type: (str) -> Union[Tuple[Netloc, pathlib.PosixPath], None]
    """Get the netloc and path from jceks:// path."""
    if not uri:
        return None

    parsed = urlparse(uri) # type: ParseResult
    if parsed.scheme != "jceks":
        return None

    netloc = Netloc.from_str(parsed.netloc)
    return (netloc, pathlib.Path(parsed.path))

def build_classpath(directory="/var/lib/ambari-agent/cred/lib", hadoop_conf_dir="/etc/hadoop/conf", *args): # pylint: disable=keyword-arg-before-vararg
    # type: (str, str, *str) -> str
    """Get files from specified directories and join them into a single ':' separated string."""
    all_args = args # type: Tuple[str, ...]
    if directory:
        all_args = (directory,) + all_args # type: Tuple[str, ...]
    if hadoop_conf_dir:
        all_args = (hadoop_conf_dir,) + all_args # type: Tuple[str, ...]

    paths = [] # type: List[List[str]]

    for arg in all_args:
        path = pathlib.PosixPath(arg).resolve() # type: pathlib.PosixPath
        if not path.exists():
            log_error("{} does not exist. Cannot continue".format(arg))
            if not running_from_ambari:
                sys.exit(1)
            else:
                return ""
        paths.append(glob.glob(path/"*"))
    list_of_files = list(itertools.chain.from_iterable(paths)) # type: List[str]
    if not list_of_files:
        log_error("No files found in any directory: {}. Cannot continue".format(args))
        if not running_from_ambari:
            sys.exit(1)
        else:
            return ""
    return ":".join(list_of_files)

def get_java_version():
    """Returns the major Java version as an integer, or None if it can't be determined."""
    # type: () -> Optional[int]
    try:
        output = subprocess.check_output(["java", "-version"], stderr=subprocess.STDOUT).decode()
        # Java version string might look like 'java version "23"'
        match = re.search(r'version "(?P<version>\d+)', output)
        if match:
            return int(match.group("version"))
    except (subprocess.CalledProcessError, OSError, UnicodeDecodeError):
        pass
    return None

def extract_password(path, alias, user=None):
    """Extract a password from a jceks file."""
    # type: (str, str, Optional[str]) -> Tuple[str, Optional[str]]
    classpath = build_classpath()

    java_version = get_java_version()

    command = ["java"]
    if java_version == 23:
        command.append("-Djava.security.manager=allow")  # Only add for JDK 23

    command += [
        "-cp",
        classpath,
        "org.apache.ambari.security.tools.GenericStorePasswordExtractor",
        "JCEKS",
        path,
        alias
    ]

    out = _run_command(command, user)

    if out.returncode != 0:
        return out.stdout, out.stderr

    return out.stdout, None

def save_password(path, alias, password, user=None):
    """Save a password to a jceks file."""
    # type: (str, str, str, Union[str, None]) -> Union[str, None]
    command = [
        "hadoop",
        "credential",
        "create",
        alias,
        "-provider",
        path,
        "-value",
        password
    ]

    path_info = get_uri_info(path) # type: Union[Tuple[Netloc, pathlib.PosixPath], None]
    if not path_info:
        return "Path: {} is not a valid path".format(path)

    netloc = path_info[0]
    jceks_path = path_info[1] # type: pathlib.PosixPath
    jceks_parent = jceks_path.parent # type: pathlib.PosixPath

    # This will return true if the parent folder already exists, or if we're able to create it
    if not _create_folder(netloc, jceks_parent):
        return "Failed to create parent directory for jceks file at {}".format(jceks_parent)

    out = _run_command(command, user)

    if out.returncode != 0:
        return out.stderr

    return None

def get_aliases(path, user=None):
    """Get a list of aliases in a jceks file."""
    # type: (str, Union[str, None]) -> Tuple[List[str], Union[str, None]]
    command = [
        "hadoop",
        "credential",
        "list",
        "-provider",
        path,
    ]

    out = _run_command(command, user)

    stderr = out.stderr

    if out.returncode != 0:
        return [], stderr.split("\n")[0]

    aliases = out.stdout.split("\n")[1:]
    if aliases and aliases[-1] == "":
        aliases.pop()
    return aliases, None

def delete_password(path, alias, user=None):
    """Delete a password from a jceks file."""
    # type: (str, str, Union[str, None]) -> Union[str, None]
    command = [
        "hadoop",
        "credential",
        "delete",
        alias,
        "-f",
        "-provider",
        path,
    ]

    out = _run_command(command, user)

    if out.returncode != 0:
        return out.stderr
    return None

def update_password(path, alias, password, user=None):
    """Change a password in a jceks file. Deletes the original, then inserts the updated value."""
    # type: (str, str, str, Union[str, None]) -> Tuple[Union[str, None], Union[str, None]]
    return delete_password(path, alias, user), save_password(path, alias, password, user)

def revert_env_vars(credstore_password, status=False):
    # type: (Union[str, None], bool) -> bool
    if credstore_password:
        os.environ["HADOOP_CREDSTORE_PASSWORD"] = credstore_password
    return status

def delete_jceks_file(jceks_path):
    "Remove a jceks file and its associated .crc file. Returns True on success."
    # type: (str) -> bool
    result = get_uri_info(jceks_path) # type: Union[Tuple[Netloc, pathlib.PosixPath], None]
    if not result:
        return False
    destination_type = result[0] # type: Netloc
    path = pathlib.PosixPath(result[1])
    file_name = path.name
    jceks_dot_file = path.parent / ".{}.crc".format(file_name) # type: pathlib.PosixPath
    if destination_type == Netloc.FILE:
        if running_from_ambari and sudo.path_exists(str(path)):
            sudo.unlink(str(path))
            if sudo.path_exists(str(jceks_dot_file)):
                sudo.unlink(str(jceks_dot_file))

        elif path.exists() and os.access(path, os.W_OK):
            os.remove(path)
            if jceks_dot_file.exists() and os.access(jceks_dot_file, os.W_OK): # pylint: disable=no-member
                os.remove(jceks_dot_file)
        elif path.exists() and not os.access(path, os.W_OK):
            log_error("Cannot delete jceks at {} because you don't have write permissions".format(path))
            return False

        if path.exists() or jceks_dot_file.exists(): # pylint: disable=no-member
            return False
    if destination_type == Netloc.HDFS:
        raise NotImplementedError("Deleting from HDFS is not yet implemented")
    return True

def test_jceks(jceks_path, password, user): # pylint: disable=too-many-return-statements
    # type: (str, Union[str, None], Union[str, None]) -> bool
    hadoop_credstore_password = os.environ.get("HADOOP_CREDSTORE_PASSWORD", None)

    if password:
        os.environ["HADOOP_CREDSTORE_PASSWORD"] = password

    result = delete_jceks_file(jceks_path)
    if not result:
        log_error("Failed to delete jceks file at {}".format(jceks_path))
        return revert_env_vars(hadoop_credstore_password, False)

    result = save_password(jceks_path, "test_password", "hadoop@123", user=user)

    if result is not None:
        log_error("Saving 'test_password' to jceks failed!")
        log_error(result.split("\n")[0])
        return revert_env_vars(hadoop_credstore_password, False)

    result = save_password(jceks_path, "delete_me", "fake_password", user=user)
    if result is not None:
        log_error("Saving 'delete_me' to jceks failed!")
        log_error(result.split("\n")[0])
        return revert_env_vars(hadoop_credstore_password, False)

    result = delete_password(jceks_path, "delete_me", user=user)
    if result is not None:
        log_error("Deleting 'delete_me' failed!")
        log_error(result.split("\n")[0])
        return revert_env_vars(hadoop_credstore_password, False)

    alias_test = get_aliases(jceks_path, user=user)
    if alias_test[1] or "delete_me" in alias_test[0] or "test_password" not in alias_test[0]:
        log_error("Incorrect aliases found in result of getting all aliases")
        log_error(alias_test[1])
        return revert_env_vars(hadoop_credstore_password, False)

    delete_error, save_error = update_password(jceks_path, "test_password", "hadoop@234", user=user)
    if delete_error is not None or save_error is not None:
        log_error("Failed to update 'test_password'")
        if delete_error:
            log_error("Delete error: {}".format(delete_error))
        if save_error:
            log_error("Save error: {}".format(save_error))
        return False

    out, error = extract_password(jceks_path, "test_password", user=user)
    if out != "hadoop@234" or error:
        log_error("Failed to get 'test_password'")
        log_error(error)
        return revert_env_vars(hadoop_credstore_password, False)

    return revert_env_vars(hadoop_credstore_password, True)

def interactive():
    # type: () -> None
    parser = argparse.ArgumentParser(
        prog="security_credential_helper",
        description="Create and manage passwords in a JCEKS file",
    )

    try:
        _, columns = os.popen('stty size', 'r').read().split()
        os.environ["COLUMNS"] = str(columns)
    except Exception: # pylint: disable=broad-except
        # This can make the help message look a little nicer
        # If it fails, ignore it
        pass

    update_delete_group = parser.add_mutually_exclusive_group()
    alias_all_group = parser.add_mutually_exclusive_group()

    parser.add_argument(
        "-f",
        "--file",
        help="Path to your jceks file. This must start with jceks://file.",
        required=True,
    )
    parser.add_argument(
        "-p",
        "--password",
        help="The password to save to the jceks file",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        help="Ignore errors",
        action="store_true",
    )
    parser.add_argument(
        "--user",
        help="The user to run the command with. This will only work if you have superuser privileges",
        default=None,
    )
    parser.add_argument(
        "-t",
        "--tests",
        help="Run tests to verify functionality. If you run the tests with --user,\
        that user must have write access to the jceks file",
        action="store_true",
    )
    parser.add_argument(
        "-x",
        "--delete_jceks",
        help="Delete a jceks file and its associated .crc file",
        action="store_true",
    )

    update_delete_group.add_argument("-u", "--update", help="Update an existing password", action="store_true")
    update_delete_group.add_argument("-d", "--delete", help="Delete an existing alias", action="store_true")

    alias_all_group.add_argument("-g", "--get-all", help="Get all aliases in a jceks file", action="store_true")
    alias_all_group.add_argument("-a", "--alias", help="The alias you want to save or retrieve")

    args = parser.parse_args()

    if not (args.get_all or args.alias or args.tests or args.delete_jceks):
        parser.error("the following argument is required: -a/--alias (unless -g/--get-all is used)")


    jceks = str(
        pathlib.PosixPath(args.file).expanduser().resolve()) \
    if not args.file.startswith("jceks://") \
    else args.file # type: str
    alias = args.alias
    password = args.password
    error = None # type: Union[str, None]
    update_error = None # type: Union[Tuple[Union[str, None], Union[str, None]], None]
    output = None # type: Union[str, None]
    user = args.user # type: Union[str, None]
    aliases = None # type: Union[List[str], None]
    delete_file = args.delete_jceks # type: bool

    if args.tests:
        print("This may take some time...")
        if not user:
            print("Running test for passwordless jceks")

            if test_jceks(jceks, None, user=None):
                print("Passwordless test passed successfully!\n")
            else:
                print("Passwordless test failed!", file=sys.stderr)
                sys.exit(1)
            print("Running test for password protected jceks")

            if test_jceks(jceks, password="my_test_password", user=None):
                print("Password protected jceks test passed successfully!")
            else:
                print("Password protected jceks test failed!", file=sys.stderr)
                sys.exit(1)
        else:
            print("Running passwordless tests as '{}'".format(user))

            if test_jceks(jceks, None, user=user):
                print("Passwordless test with '{}' passed successfully!\n".format(user))
            else:
                print("Passwordless test with '{}' failed!".format(user), file=sys.stderr)
                sys.exit(1)

            print("Running test with '{}' for password protected jceks".format(user))

            if test_jceks(jceks, password="my_test_password", user=user):
                print("Password protected jceks with '{}' test passed successfully!".format(user))
            else:
                print("Password protected jceks with '{}' test failed!".format(user), file=sys.stderr)
                sys.exit(1)

        sys.exit(0)

    if args.get_all:
        aliases, error = get_aliases(jceks, user=user)

    elif args.update:
        update_error = update_password(jceks, alias, password, user=user)

    elif args.delete:
        error = delete_password(jceks, alias, user=user)

    elif args.delete_jceks:
        if not delete_jceks_file(jceks):
            log_error("Failed to delete jceks file at {}".format(delete_file))
            sys.exit(1)

    elif args.password:
        error = save_password(jceks, alias, password, user=user)

    elif args.alias:
        output, error = extract_password(jceks, alias, user=user)

    if not output and (error or update_error):
        if not args.quiet:
            if update_error:
                if update_error[0]:
                    print("Error deleting alias '{}': {}".format(alias, update_error[0]), file=sys.stderr)
                if update_error[1]:
                    print("Error saving alias '{}': {}".format(alias, update_error[1]), file=sys.stderr)
            elif error:
                print(error.strip(), file=sys.stderr)
        sys.exit(1)

    elif aliases is not None:
        if aliases:
            print(aliases)
        else:
            if not args.quiet:
                print("No aliases found in {}".format(jceks), file=sys.stderr)
            sys.exit(1)

    elif output:
        if output.strip() == "null":
            print("No entry found for alias '{}'".format(alias), file=sys.stderr)
        else:
            print(output)

if __name__ == "__main__":
    interactive()
