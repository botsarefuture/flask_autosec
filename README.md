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

## Documentation
Detailed documentation can be found in the `docs/` folder.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.