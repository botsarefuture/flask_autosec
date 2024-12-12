"""
This module provides the FlaskAutoSec library for integrating security features into a Flask application.
It includes functionalities for mode management, SEC violation handling, request reporting, blacklist checking, and rate-limiting.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

UNAUTHORIZED USE OF THIS SOFTWARE IS STRICTLY PROHIBITED.

Author: Verso Vuorenmaa

Version: 0.1.0

THIS CODE AND IT'S USING IS UNDER NDA AGREEMENT WITH LUOVACLUB RY.
"""

from flask import jsonify
from flask import redirect
from flask import request
from flask import abort
from flask import make_response
from flask import current_app
import asyncio
import aiohttp
from apscheduler.schedulers.background import BackgroundScheduler
import logging
from collections import defaultdict
import time
from blacklistfetcher import BlacklistFetcher
import requests
import re

logger = logging.getLogger("FlaskAutoSec")
logger.setLevel(logging.WARNING)

# Check if we have internet connection if not, raise PanicError
global INTERNET_CONNECTION
INTERNET_CONNECTION = False

def wait_for_internet():
    """
    Waits for an internet connection to be established.
    """
    global INTERNET_CONNECTION
    while not INTERNET_CONNECTION:
        logger.info("Checking for internet connection...")
    
        try:
            try:
                requests.get("https://core.security.luova.club", timeout=5)
                INTERNET_CONNECTION = True
            
            except requests.ConnectionError:
                logger.error("No internet connection detected.")
                logger.warning("Trying again in 5 seconds... (Press CTRL+C to continue without internet connection)")
                time.sleep(5)
                continue
            
        except KeyboardInterrupt:
        # let the user continue without internet connection
            logger.warning("Continuing without internet connection.")
            INTERNET_CONNECTION = True
            break
        
    
        
wait_for_internet()

def check_internet_connection():
    """
    Checks if there is an internet connection and logs the status.
    """
    if INTERNET_CONNECTION:
        logger.info("Internet connection detected or user chose to continue without it.")

    else:
        logger.warning("Something shady is going on. Exiting for security reasons.")

check_internet_connection()
    
class Mode:
    """
    Represents the mode.
    
    Attributes
    ----------
    mode : int
        The mode as int:
            - 0: pink
            - 1: blue
            - 2: red
            - 3: violet
            - 4: darkred
            - 5: black
            
    Methods
    -------
    __str__()
        Returns the mode as a string.
    
    __repr__()
        Returns the mode as a string.
        
    __int__()
        Returns the mode as an int.
    
    _update()
        Updates the mode.
        
    _upper()
        Returns the mode as an uppercase string.
    """
    
    PINK = 0
    BLUE = 1
    RED = 2
    VIOLET = 3
    DARKRED = 4
    BLACK = 5
    WHITE = 6
    
    def __init__(self, mode=None):
        """
        Initializes the Mode instance.

        Parameters
        ----------
        mode : int, optional
            The initial mode (default is None).
        """
        self.mode = mode
        
        if self.mode is None:
            self._init_mode()
        
    def _init_mode(self):
        """
        Initializes the mode by fetching it from the SECORE API.
        """
        self.mode = self.fetch_mode()
        
    def _as_real_string(self):
        """
        Converts the mode to its corresponding string representation.

        Returns
        -------
        str
            The string representation of the mode.
        """
        #if type(self.mode) == str:
        #    self.mode = int(self.mode)
            
        if self.mode == 0:
            return "pink"
        
        elif self.mode == 1:
            return "blue"
        
        elif self.mode == 2:
            return "red"
        
        elif self.mode == 3:
            return "violet"
        
        elif self.mode == 4:
            return "darkred"
        
        elif self.mode == 5:
            return "black"
        
        elif self.mode == 6:
            return "white"
        
        else:
            return "black"
        
    def fetch_mode(self):
        """
        Fetches the mode from the SECORE API.

        Returns
        -------
        int
            The fetched mode.
        """
        try:
            url = "https://core.security.luova.club/visualizer/api/alertlevel"
            result = requests.get(url)
            resp = int(result.json().get("alert_level", 0))
            return resp
        except:
            return 5 # If the request fails, return black mode.
    
    def __str__(self):
        """
        Returns the string representation of the mode.

        Returns
        -------
        str
            The string representation of the mode.
        """
        return str(self._as_real_string())
    
    def __repr__(self):
        """
        Returns the mode as an integer.

        Returns
        -------
        int
            The mode as an integer.
        """
        return self.mode
    
    def __int__(self):
        """
        Returns the mode as an integer.

        Returns
        -------
        int
            The mode as an integer.
        """
        return int(self.mode)
    
    def _update(self):
        """
        Updates the mode by fetching the latest mode from the SECORE API.
        """
        self.mode = self.fetch_mode()
    
    def _upper(self):
        """
        Returns the mode as an uppercase string.

        Returns
        -------
        str
            The uppercase string representation of the mode.
        """
        return self._as_real_string().upper()

class SecViolation(Exception):
    """
    Exception raised for SEC violations.
    
    Attributes
    ----------
    message : str
        The exception message.
    
    Methods
    -------
    report_violation()
        Asynchronously reports the SEC violation to the SECORE API.
    
    abort_request()
        Aborts the current request with a 403 Forbidden status.
    """
    def __init__(self, message="SEC violation detected"):
        """
        Initializes the SecViolation exception.

        Parameters
        ----------
        message : str, optional
            The exception message (default is "SEC violation detected").
        """
        self.message = message
        super().__init__(self.message)
        asyncio.run(self.report_violation())
        self.abort_request()

    async def report_violation(self):
        """
        Asynchronously reports the SEC violation to the SECORE API.
        """
        async with aiohttp.ClientSession() as session:
            try:
                await session.post(
                    "https://core.security.luova.club/HTTP/reports",
                    json={
                        'message': self.message,
                        'type': 'sec_violation'
                    }
                )
            except aiohttp.ClientError as e:
                logger.error(f"Error reporting SEC violation to SECORE API: {e}")

    def abort_request(self):
        """
        Aborts the current request with a 403 Forbidden status.
        """
        response = make_response("Forbidden: SEC violation detected", 403)
        response.headers['X-Error-Code'] = '403'
        abort(response)

class FlaskAutoSec:
    """
    FlaskAutoSec library for integrating security features into a Flask application.
    
    Attributes
    ----------
    app : Flask
        The Flask application instance.
    api_base_url : str
        The SECORE API base URL.
    reports_url : str
        The URL for reporting to SECORE API.
    blacklist_fetcher : BlacklistFetcher
        The blacklist fetcher instance.
    _enforce_rate_limits : bool
        Flag to enforce rate limits.
    rate_limits : dict
        Dictionary of rate limits for different modes.
    current_rate_limit : int
        The current rate limit.
    blacklist : set
        Set of blacklisted IP addresses.
    whitelist : list
        List of whitelisted IP addresses.
    request_counts : defaultdict
        Dictionary to track request counts and reset times.
    mode : int
        The current mode.
    
    Methods
    -------
    init_app(app)
        Initializes the extension with the Flask app.
    _add_to_whitelist(ip)
        Adds an IP address to the whitelist.
    _handle_white_mode()
        Handles the white mode.
    _setup_routes(app)
        Sets up Flask hooks for request reporting, blacklist checking, and rate-limiting.
    get_ip()
        Retrieves the client's IP address from the request headers.
    _is_valid_ip(ip)
        Validates the format of an IP address.
    _report_request(response)
        Asynchronously reports a request to the SECORE API.
    _report_rate_limit_violation(ip)
        Asynchronously reports a rate limit violation to the SECORE API.
    _fetch_mode_and_update_limits()
        Fetches the current mode from SECORE API and updates rate limits accordingly.
    _start_scheduler()
        Starts a scheduler to periodically update mode and blacklist.
    """
    def __init__(self, _enforce_rate_limits=False):
        """
        Initializes the FlaskAutoSec library.

        Parameters
        ----------
        _enforce_rate_limits : bool, optional
            Flag to enforce rate limits (default is False).
        """
        self._enforce_rate_limits = _enforce_rate_limits
        self.api_base_url = "https://core.security.luova.club/"
        self.reports_url = f'{self.api_base_url}/HTTP/reports'
        self.blacklist_fetcher = BlacklistFetcher()
        
        self.rate_limits = {
            'pink': 5,
            'blue': 250,
            'red': 200,
            'violet': 150,
            'darkred': 100,
            'black': 50
        }
        
        self.current_rate_limit = self.rate_limits['pink']
        self.blacklist = set()
        self.whitelist = ["127.0.0.1"]
        self.request_counts = defaultdict(lambda: {'count': 0, 'reset_time': time.time() + 60}) # 60 seconds
        self.mode: int = 0

    def init_app(self, app):
        """
        Initializes the extension with the Flask app.

        Parameters
        ----------
        app : Flask
            The Flask application instance.
        """
        self._setup_routes(app)
        self._start_scheduler()

    def _add_to_whitelist(self, ip):
        """
        Adds an IP address to the whitelist.

        Parameters
        ----------
        ip : str
            The IP address to add.
        """
        self.whitelist.append(ip)
    
    def _handle_white_mode(self):
        """
        Handles the white mode.
        
        Returns
        -------
        Response
            The response object.
        """
        if self.mode != 6:
            return
        # When mode is 6 (Code White), 
        # redirect user to underattack.luova.club
        # with 503 status code.
        if self.mode == 6:
            if request.is_json:
                return jsonify({"message": "Service Unavailable"}), 503
            
            return redirect("https://underattack.luova.club", 503)
                
    
    def _setup_routes(self, app):
        """
        Sets up Flask hooks for request reporting, blacklist checking, and rate-limiting.
        """
        @app.before_request
        def check_blacklist_and_rate_limit():
            """
            Checks if the request IP is in the blacklist and aborts the request if it is.
            Also enforces rate limits for the IP.
            """
            kill_req = False
            
            ip = self.get_ip()
            _fetch = request.headers.get("Sec-Fetch-Mode") == "cors"

            logger.warning(request.user_agent)
            
            
            
            if self.mode == 6:
                kill_req = True
                return self._handle_white_mode()
            
            # Blacklist check
            if ip in self.blacklist:
                if _fetch: #JSON request
                    return jsonify({"error": "Forbidden: IP blacklisted"}), 403
                
                response = make_response("Forbidden: IP blacklisted", 403)
                response.headers['X-Error-Code'] = '403.6'
                kill_req = True
                abort(response)

            # Rate limiting
            current_time = time.time()
            if current_time > self.request_counts[ip]['reset_time']:
                self.request_counts[ip]['count'] = 0
                self.request_counts[ip]['reset_time'] = current_time + 60

            self.request_counts[ip]['count'] += 1
            if self.request_counts[ip]['count'] > self.current_rate_limit and self._enforce_rate_limits:
                # Report rate limit violation to SECORE asynchronously
                asyncio.run(self._report_rate_limit_violation(ip))

                response = make_response("Too Many Requests", 429)
                response.headers['X-RateLimit-Limit'] = str(self.current_rate_limit)
                response.headers['X-RateLimit-Remaining'] = '0'
                response.headers['Retry-After'] = str(int(self.request_counts[ip]['reset_time'] - current_time))
                
                # render html page with 429 status code
                response.headers['Content-Type'] = 'text/html'
                response.data = "<html><head><title>429 Too Many Requests</title></head><body><h1>Too Many Requests</h1><p>I'm sorry, you have exceeded the rate limit.</p></body></html>"
                response.headers['Refresh'] = str(int(self.request_counts[ip]['reset_time'] - current_time))
                
                if _fetch:
                    return jsonify({"error": "Rate limit exceeded", "e_code": "RATELIMIT_EXCEEDED"}), 429
                
                # Handle rate limit violation gracefully
                return response
                
                kill_req = True
                abort(response)
                
            if kill_req:
                # raise some error that causes the request to crash
                raise SecViolation("The request was killed.")
                
                logger.error("The request didn't get killed.")
                logger.error("Exiting for security reasons.")
                exit(1)

        @app.after_request
        def report_request(response):
            """
            Reports the request to SECORE API asynchronously.

            Parameters
            ----------
            response : Response
                The Flask response object.

            Returns
            -------
            Response
                The original response object.
            """
            asyncio.run(self._report_request(response))
                
            return response

    def get_ip(self):
        """
        Retrieves the client's IP address from the request headers.

        Returns
        -------
        str
            The client's IP address.
        """
        if 'X-Forwarded-For' in request.headers:
            # X-Forwarded-For can contain multiple IPs, take the first one
            ip = request.headers['X-Forwarded-For'].split(',')[0].strip()
        else:
            ip = request.remote_addr

        # Validate IP address format
        if not self._is_valid_ip(ip):
            logger.warning(f"Invalid IP address detected: {ip}")
            raise SecViolation(f"Invalid IP address detected: {ip}")

        return ip

    def _is_valid_ip(self, ip):
        """
        Validates the format of an IP address.

        Parameters
        ----------
        ip : str
            The IP address to validate.

        Returns
        -------
        bool
            True if the IP address is valid, False otherwise.
        """
        ip_pattern = re.compile(
            r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'  # IPv4 pattern
            r'|'
            r'^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$'  # IPv6 pattern
        )
        return bool(ip_pattern.match(ip))
    
    async def _report_request(self, response):
        """
        Asynchronously reports a request to the SECORE API.

        Parameters
        ----------
        response : Response
            The Flask response object.
        """
        async with aiohttp.ClientSession() as session:
            try:
                await session.post(
                    self.reports_url,
                    json={
                        'method': request.method,
                        'path': request.path,
                        'status_code': response.status_code,
                        'ip': self.get_ip(),
                        'type': 'request'
                    }
                )
            except aiohttp.ClientError as e:
                logger.error(f"Error reporting request to SECORE API: {e}")

    async def _report_rate_limit_violation(self, ip):
        """
        Asynchronously reports a rate limit violation to the SECORE API.

        Parameters
        ----------
        ip : str
            The IP address of the client exceeding the rate limit.
        """
        async with aiohttp.ClientSession() as session:
            try:
                await session.post(
                    self.reports_url,
                    json={
                        'method': request.method,
                        'path': request.path,
                        'status_code': 429,
                        'ip': ip,
                        'message': 'Rate limit exceeded',
                        'type': 'rate_limit_violation'
                    }
                )
            except aiohttp.ClientError as e:
                logger.error(f"Error reporting rate limit violation to SECORE API: {e}")

    def _fetch_mode_and_update_limits(self):
        """
        Fetches the current mode from SECORE API and updates rate limits accordingly.
        Also fetches the blacklist from SECORE API and updates the local blacklist.
        """
        try:
            # Fetch mode
            mode = Mode()
            mode._update()
            
            self.mode = int(mode)
            
            self.current_rate_limit = self.rate_limits.get(str(mode._upper()), self.rate_limits['pink'])
            
            if self.mode == 5:
                logger.warning("Black mode detected. Enforcing rate limits.")
                self._enforce_rate_limits = True
                

            # Fetch blacklist
            blacklist_response = self.blacklist_fetcher.get_blacklist_ips()
            self.blacklist = set(blacklist_response)
            
        except requests.RequestException as e:
            logger.error(f"Error fetching data from SECORE API: {e}")

    def _start_scheduler(self):
        """
        Starts a scheduler to periodically update mode and blacklist.
        """
        scheduler = BackgroundScheduler()
        scheduler.add_job(self._fetch_mode_and_update_limits, 'interval', minutes=1)
        scheduler.start()

        # Initial fetch
        self._fetch_mode_and_update_limits()