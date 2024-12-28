# FlaskAutoSec

FlaskAutoSec is a library for integrating security features into a Flask application. It includes functionalities for mode management, SEC violation handling, request reporting, blacklist checking, and rate-limiting.

## Installation
```bash
pip install git+https://github.com/botsarefuture/flask_autosec.git
```

## Usage
```python
from flask import Flask
from flask_autosec import FlaskAutoSec

app = Flask(__name__)
security = FlaskAutoSec()
security.init_app(app)

if __name__ == '__main__':
    app.run()
```

### Running with Gunicorn

When deploying your Flask application with Gunicorn, FlaskAutoSec ensures that only one scheduler instance runs across multiple worker processes. This is achieved using a file-based lock mechanism.

**Example Command:**
```bash
gunicorn -w 4 -b 0.0.0.0:8000 your_application:app
```

**Notes:**
- The scheduler lock file is located at `/tmp/flask_autosec_scheduler.lock`. Ensure that the application has the necessary permissions to create and modify this file.
- FlaskAutoSec automatically detects if it's running under Gunicorn and handles scheduler initialization accordingly to prevent multiple instances.

## Documentation
Detailed documentation can be found in the `docs/` folder.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.