"""Certbot external plugin."""
import os
import logging
import pipes
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

import zope.component
import zope.interface

from urlparse import urlparse
from acme import challenges

from certbot import errors
from certbot import interfaces
from certbot.plugins import common


logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(common.Plugin):
    """external Authenticator.

    This plugin requires an external executable which accepts two args
    (challenge uri and validation string). The external executable should
    set up the external http(s) server which will receive the challenge
    request from the ACME server and it should exit with code 0 if the 
    external web server is successfully set up.

    """
    description = "Configure web server(s) with given executable"

    MESSAGE_TEMPLATE = """\
Setting up external web server to display the following content at
{uri}:

{validation}

"""

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)

    @classmethod
    def add_parser_arguments(cls, add):
        add("exec", "--external-auth-exec",
            help="External executable path")
        add("exec-interpreter", "--external-auth-exec-interpreter",
            help="executable interpreter, default to '/bin/bash'.")

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        pass

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return ("This plugin requires an executable to set up an "
                "external HTTP server for solving http-01 challenges.")

    def get_chall_pref(self, domain):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        return [challenges.HTTP01]

    def perform(self, achalls):  # pylint: disable=missing-docstring
        responses = []
        for achall in achalls:
            responses.append(self._perform_single(achall))
        return responses

    def _info(self,msg,stdout=True):
        logger.info(msg)
        if stdout == True:
            print(msg)

    def _run_exec(self, uri, validation):
        exec_interpreter = self.conf('exec-interpreter')
        exec_path = self.conf('exec')

        self._info('')
        self._info('===============================')
        if exec_interpreter != None and exec_interpreter != '':
            self._info('interpreter: {0}'.format(exec_interpreter))
        self._info('executable:  {0}'.format(exec_path))
        self._info('uri:         {0}'.format(uri))
        self._info('content:     {0}'.format(validation))
        self._info('===============================')

        self._info('')
        self._info('running ...')
        cmds = None
        if exec_interpreter != None and exec_interpreter != '':
            cmds = [exec_interpreter, exec_path, uri, validation]
        else:
            cmds = [exec_path, uri, validation]

        proc = subprocess.Popen(cmds,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        self._info('exit code: {0}'.format(proc.returncode))
        self._info('[stdout]')
        self._info(stdout)
        self._info('[stderr]')
        self._info(stderr)

        return proc.returncode == 0

    def _perform_single(self, achall):
        response, validation = achall.response_and_validation()

        url = achall.chall.uri(achall.domain)
        sys.stdout.write(self.MESSAGE_TEMPLATE.format(
            validation=validation, uri=url))

        if self._run_exec(urlparse(url).path, validation) == True:
            if not response.simple_verify(
                    achall.chall, achall.domain,
                    achall.account_key.public_key(), self.config.http01_port):
                logger.warning("Self-verify of challenge failed.")
        else:
            raise errors.PluginError('external executable exits with non-zero code!')

        return response

    def cleanup(self, achalls):
        # pylint: disable=missing-docstring,no-self-use,unused-argument
        pass
