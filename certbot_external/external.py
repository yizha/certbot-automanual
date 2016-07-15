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
def _info(msg,stdout=True):
    logger.info(msg)
    if stdout == True:
        print(msg)



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
        add("auth-exec", "--external-auth-exec",
            help="External executable path")
        add("auth-exec-interpreter", "--external-auth-exec-interpreter",
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

    def _run_external_setup(self, uri, validation):
        exec_interpreter = self.conf('auth-exec-interpreter')
        exec_path = self.conf('auth-exec')
        if exec_path == None or exec_path == '':
            raise errors.PluginError('auth external executable not given!')

        _info('')
        _info('===============================')
        if exec_interpreter != None and exec_interpreter != '':
            _info('interpreter: {0}'.format(exec_interpreter))
        _info('executable:  {0}'.format(exec_path))
        _info('uri:         {0}'.format(uri))
        _info('content:     {0}'.format(validation))
        _info('===============================')

        _info('')
        _info('running ...')
        cmds = None
        if exec_interpreter != None and exec_interpreter != '':
            cmds = [exec_interpreter, exec_path, uri, validation]
        else:
            cmds = [exec_path, uri, validation]

        proc = subprocess.Popen(cmds,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        _info('exit code: {0}'.format(proc.returncode))
        _info('[stdout]')
        _info(stdout)
        _info('[stderr]')
        _info(stderr)

        return proc.returncode == 0

    def _perform_single(self, achall):
        response, validation = achall.response_and_validation()

        url = achall.chall.uri(achall.domain)
        sys.stdout.write(self.MESSAGE_TEMPLATE.format(
            validation=validation, uri=url))

        if self._run_external_setup(urlparse(url).path, validation) == True:
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


@zope.interface.implementer(interfaces.IInstaller)
@zope.interface.provider(interfaces.IPluginFactory)
class Installer(common.Plugin):
    """external Installer.

    This plugin requires an external executable which accepts four paths 
    as args, they are cert,key,chain and fullchain. The external
    executable should install the cert and restart the service if needed.

    """
    description = "Install cert with given executable"

    @classmethod
    def add_parser_arguments(cls, add):
        add("install-exec", "--external-install-exec",
            help="External executable path")
        add("install-exec-interpreter", "--external-install-exec-interpreter",
            help="executable interpreter, default to '/bin/bash'.")

    def prepare(self):  # pylint: disable=missing-docstring,no-self-use
        pass

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return ("This plugin requires an executable to install "
                "the given cert.")

    def get_all_names(self):
        """Returns all names that may be authenticated.
        :rtype: `list` of `str`
        """
        return []

    def deploy_cert(self, domain, cert_path, key_path, chain_path, fullchain_path):
        """Deploy certificate.
        :param str domain: domain to deploy certificate file
        :param str cert_path: absolute path to the certificate file
        :param str key_path: absolute path to the private key file
        :param str chain_path: absolute path to the certificate chain file
        :param str fullchain_path: absolute path to the certificate fullchain
            file (cert plus chain)
        :raises .PluginError: when cert cannot be deployed
        """
        exec_interpreter = self.conf('install-exec-interpreter')
        exec_path = self.conf('install-exec')
        if exec_path == None or exec_path == '':
            raise errors.PluginError('install external executable not given!')

        _info('')
        _info('===============================')
        if exec_interpreter != None and exec_interpreter != '':
            _info('interpreter:    {0}'.format(exec_interpreter))
        _info('executable:     {0}'.format(exec_path))
        _info('domain:         {0}'.format(domain))
        _info('cert file:      {0}'.format(cert_path))
        _info('key file:       {0}'.format(key_path))
        _info('chain file:     {0}'.format(chain_path))
        _info('fullchain file: {0}'.format(fullchain_path))
        _info('===============================')

        _info('')
        _info('running ...')
        cmds = None
        if exec_interpreter != None and exec_interpreter != '':
            cmds = [exec_interpreter, exec_path, domain, cert_path, key_path, chain_path, fullchain_path]
        else:
            cmds = [exec_path, domain, cert_path, key_path, chain_path, fullchain_path]

        proc = subprocess.Popen(cmds,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()

        _info('exit code: {0}'.format(proc.returncode))
        _info('[stdout]')
        _info(stdout)
        _info('[stderr]')
        _info(stderr)

        if proc.returncode != 0:
            raise errors.PluginError('deploy cert failed with {0}!'.format(exec_path))
        else:
            _info('successfully deployed cert with {0}'.format(exec_path))

    def enhance(self, domain, enhancement, options=None):
        """Perform a configuration enhancement.
        :param str domain: domain for which to provide enhancement
        :param str enhancement: An enhancement as defined in
            :const:`~certbot.constants.ENHANCEMENTS`
        :param options: Flexible options parameter for enhancement.
            Check documentation of
            :const:`~certbot.constants.ENHANCEMENTS`
            for expected options for each enhancement.
        :raises .PluginError: If Enhancement is not supported, or if
            an error occurs during the enhancement.
        """
        pass

    def supported_enhancements(self):
        """Returns a list of supported enhancements.
        :returns: supported enhancements which should be a subset of
            :const:`~certbot.constants.ENHANCEMENTS`
        :rtype: :class:`list` of :class:`str`
        """
        return []

    def get_all_certs_keys(self):
        """Retrieve all certs and keys set in configuration.
        :returns: tuples with form `[(cert, key, path)]`, where:
            - `cert` - str path to certificate file
            - `key` - str path to associated key file
            - `path` - file path to configuration file
        :rtype: list
        """
        return []

    def save(self, title=None, temporary=False):
        """Saves all changes to the configuration files.
        Both title and temporary are needed because a save may be
        intended to be permanent, but the save is not ready to be a full
        checkpoint.
        It is assumed that at most one checkpoint is finalized by this
        method. Additionally, if an exception is raised, it is assumed a
        new checkpoint was not finalized.
        :param str title: The title of the save. If a title is given, the
            configuration will be saved as a new checkpoint and put in a
            timestamped directory. `title` has no effect if temporary is true.
        :param bool temporary: Indicates whether the changes made will
            be quickly reversed in the future (challenges)
        :raises .PluginError: when save is unsuccessful
        """
        pass

    def rollback_checkpoints(self, rollback=1):
        """Revert `rollback` number of configuration checkpoints.
        :raises .PluginError: when configuration cannot be fully reverted
        """
        pass

    def recovery_routine(self):
        """Revert configuration to most recent finalized checkpoint.
        Remove all changes (temporary and permanent) that have not been
        finalized. This is useful to protect against crashes and other
        execution interruptions.
        :raises .errors.PluginError: If unable to recover the configuration
        """
        pass

    def view_config_changes(self):
        """Display all of the LE config changes.
        :raises .PluginError: when config changes cannot be parsed
        """
        pass

    def config_test(self):
        """Make sure the configuration is valid.
        :raises .MisconfigurationError: when the config is not in a usable state
        """
        pass

    def restart(self):
        """Restart or refresh the server content.
        :raises .PluginError: when server cannot be restarted
        """
        pass
