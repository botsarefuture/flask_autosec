Usage
=====

To use FlaskAutoSec in your Flask application, follow these steps:

.. code-block:: python

    from flask import Flask
    from flask_autosec import FlaskAutoSec

    app = Flask(__name__)
    security = FlaskAutoSec(_enforce_rate_limits=True)
    security.init_app(app)

    if __name__ == '__main__':
        app.run()

### Deployment with Gunicorn

When deploying your Flask application with Gunicorn, FlaskAutoSec ensures that only one scheduler instance runs across multiple worker processes. This is achieved using a file-based lock mechanism.

**Example Command:**

.. code-block:: bash

    gunicorn -w 4 -b 0.0.0.0:8000 your_application:app

**Notes:**
- The scheduler lock file is located at `/tmp/flask_autosec_scheduler.lock`. Ensure that the application has the necessary permissions to create and modify this file.
- FlaskAutoSec automatically detects if it's running under Gunicorn and handles scheduler initialization accordingly to prevent multiple instances.