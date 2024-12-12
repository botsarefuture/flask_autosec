from setuptools import setup, find_packages

setup(
    name='flask_autosec',
    version='0.3.0',
    author='Verso Vuorenmaa',
    description='FlaskAutoSec library for integrating security features into a Flask application.',
    packages=find_packages(),
    install_requires=[
        'Flask>=1.1.2',
        'aiohttp>=3.7.4',
        'APScheduler>=3.6.3',
        'requests>=2.25.1',
        'blacklistfetcher @ git+https://github.com/botsarefuture/blacklistfetcher.git'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
