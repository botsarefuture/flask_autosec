
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