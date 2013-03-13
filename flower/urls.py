from __future__ import absolute_import

from tornado.web import StaticFileHandler

from .views.workers import (
    WorkersView,
    WorkerView,
)

from .views.tasks import (
    TaskView,
    TasksView,
)

from .views import auth

from .api import events
from .api import control
from .api import tasks
from .api import workers

from .views.update import (
    UpdateWorkers,
)

from .views.monitor import (
    Monitor,
    SucceededTaskMonitor,
    FailedTaskMonitor,
    TimeToCompletionMonitor,
)


from .views.error import NotFoundErrorHandler
from .settings import APP_SETTINGS
import functools
import base64


_handlers = [
    # App
    (r"/", WorkersView),
    (r"/workers", WorkersView),
    (r"/worker/(.+)", WorkerView),
    (r"/task/(.+)", TaskView),
    (r"/tasks", TasksView),
    # Worker API
    (r"/api/workers", workers.ListWorkers),
    (r"/api/worker/shutdown/(.+)", control.WorkerShutDown),
    (r"/api/worker/pool/restart/(.+)", control.WorkerPoolRestart),
    (r"/api/worker/pool/grow/(.+)", control.WorkerPoolGrow),
    (r"/api/worker/pool/shrink/(.+)", control.WorkerPoolShrink),
    (r"/api/worker/pool/autoscale/(.+)", control.WorkerPoolAutoscale),
    (r"/api/worker/queue/add-consumer/(.+)", control.WorkerQueueAddConsumer),
    (r"/api/worker/queue/cancel-consumer/(.+)",
        control.WorkerQueueCancelConsumer),
    # Task API
    (r"/api/tasks", tasks.ListTasks),
    (r"/api/task/async-apply/(.+)", tasks.TaskAsyncApply),
    (r"/api/task/result/(.+)", tasks.TaskResult),
    (r"/api/task/timeout/(.+)", control.TaskTimout),
    (r"/api/task/rate-limit/(.+)", control.TaskRateLimit),
    (r"/api/task/revoke/(.+)", control.TaskRevoke),
    # Events WebSocket API
    (r"/api/task/events/task-sent/(.*)", events.TaskSent),
    (r"/api/task/events/task-received/(.*)", events.TaskReceived),
    (r"/api/task/events/task-started/(.*)", events.TaskStarted),
    (r"/api/task/events/task-succeeded/(.*)", events.TaskSucceeded),
    (r"/api/task/events/task-failed/(.*)", events.TaskFailed),
    (r"/api/task/events/task-revoked/(.*)", events.TaskRevoked),
    (r"/api/task/events/task-retried/(.*)", events.TaskRetried),
    # WebSocket Updates
    (r"/update-workers", UpdateWorkers),
    # Monitors
    (r"/monitor", Monitor),
    (r"/monitor/succeeded-tasks", SucceededTaskMonitor),
    (r"/monitor/failed-tasks", FailedTaskMonitor),
    (r"/monitor/completion-time", TimeToCompletionMonitor),
    # Static
    (r"/static/(.*)", StaticFileHandler,
     {"path": APP_SETTINGS['static_path']}),
    # Auth
    (r"/login", auth.LoginHandler),
    (r"/logout", auth.LogoutHandler),

    # Error
    (r".*", NotFoundErrorHandler),
]

"""
    This patch adds mandatory HTTP Basic Auth to all requests, except websockets
"""

# http://kelleyk.com/post/7362319243/easy-basic-http-authentication-with-tornado
def require_basic_auth(handler_class, auth):

    def _request_auth(handler):
        if hasattr(handler, "ws_connection"):
            return True  # TODO, basic auth not supported in websockets

        handler.set_header('WWW-Authenticate', 'Basic realm=Flower')
        handler.set_status(401)
        handler._transforms = []
        handler.finish()
        return False

    def wrap_execute(handler_execute):
        def require_basic_auth(handler):
            auth_header = handler.request.headers.get('Authorization')
            if auth_header is None or not auth_header.startswith('Basic '):
                return _request_auth(handler)

            auth_decoded = base64.decodestring(auth_header[6:])

            username, password = auth_decoded.split(':', 2)

            if (auth(username, password)):
                return True
            else:
                return _request_auth(handler)
            
        def _execute(self, transforms, *args, **kwargs):
            if not require_basic_auth(self):
                return False
            return handler_execute(self, transforms, *args, **kwargs)
        return _execute

    handler_class._execute = wrap_execute(handler_class._execute)
    return handler_class


import sys
import os
sys.path.append(os.getcwd())

import config


def oxauth(username, password):
    return "%s:%s" % (username, password) == config.config["FLOWER_AUTH"]


# Force-add httpauth to each handler
handlers = []
for h in _handlers:
    if len(h) > 2:
        handlers.append((h[0], require_basic_auth(h[1], oxauth), h[2]))
    else:
        handlers.append((h[0], require_basic_auth(h[1], oxauth)))
