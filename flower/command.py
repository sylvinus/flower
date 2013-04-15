from __future__ import absolute_import

import atexit
import logging

from pprint import pformat

from tornado.options import define, options, parse_command_line

from celery.bin.base import Command

from . import settings
from .app import Flower


define("port", default=5555, help="run on the given port", type=int)
define("address", default='', help="run on the given address", type=str)
define("debug", default=False, help="run in debug mode", type=bool)
define("inspect", default=True, help="inspect workers", type=bool)
define("inspect_timeout", default=1000, type=float,
       help="inspect timeout (in milliseconds)")
define("auth", default='', type=str,
       help="comma separated list of emails to grant access")
define("url_prefix", type=str, help="base url prefix")
define("max_tasks", type=int, default=10000,
       help="maximum number of tasks to keep in memory (default 10000)")
define("db", type=str, default='flower.db', help="flower database file")
define("persistent", type=bool, default=False, help="enable persistent mode")


class FlowerCommand(Command):

    def run_from_argv(self, prog_name, argv=None):
        app_settings = settings.APP_SETTINGS
        argv = filter(self.flower_option, argv)
        parse_command_line([prog_name] + argv)
        auth = map(str.strip, options.auth.split(',')) if options.auth else []
        app_settings['debug'] = options.debug

        if options.url_prefix:
            prefix = options.url_prefix.strip('/')
            app_settings['static_url_prefix'] = '/{0}/static/'.format(prefix)
            app_settings['login_url'] = '/{0}/login'.format(prefix)
            settings.URL_PREFIX = prefix
        settings.CELERY_INSPECT_TIMEOUT = options.inspect_timeout

        # Monkey-patch to support Celery 2.5.5
        self.app.connection = self.app.broker_connection

        flower = Flower(celery_app=self.app, auth=auth, options=options,
                        **app_settings)
        atexit.register(flower.stop)

        logging.info('Visit me at http://%s:%s' %
                    (options.address or 'localhost', options.port))
        logging.info('Broker: %s', self.app.connection().as_uri())
        logging.debug('Settings: %s' % pformat(app_settings))

        try:
            flower.start()
        except (KeyboardInterrupt, SystemExit):
            pass

    def handle_argv(self, prog_name, argv=None):
        return self.run_from_argv(prog_name, argv)

    @staticmethod
    def flower_option(arg):
        name, _, value = arg.lstrip('-').partition("=")
        name = name.replace('-', '_')
        return hasattr(options, name)
