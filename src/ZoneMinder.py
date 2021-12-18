import logging
from string import ascii_uppercase
from typing import Optional, Dict, List

from sqlalchemy.exc import SQLAlchemyError

from src.ZMClasses import Events, Monitors, States, Zones, Configs
from src.ZMSession import ZMSession
from src.dataclasses import ZMEvent, ZMMonitor, ZMState, ZMZone, ZMConfig
from src.models import DBOptions, APIOptions

logger = logging.getLogger('ZM')
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_fmt = logging.Formatter(
    '%(asctime)s %(name)s[%(process)s]  %(levelname)s %(filename)s:%(lineno)d->[%(message)s]')
console_handler.setFormatter(console_fmt)
logger.addHandler(console_handler)


class MySQLHandler(logging.Handler):
    levels_no = {
        'debug': 1,
        'info': 0,
        'warning': -1,
        'error': -2,
        'critical': -3,
        'off': -5
    }
    levels_name = {
        'debug': 'DBG',
        'info': 'INF',
        'warning': 'WAR',
        'error': 'ERR',
        'panic': 'PNC',  # Not real just there for now
        'critical': 'FAT',

        'off': 'OFF'
    }

    def __init__(self, conn, table):
        super().__init__()
        self.conn = conn
        self.table = table

    def emit(self, record: logging.LogRecord):
        pid = record.process
        message = record.getMessage()
        level = record.levelname
        lvl = self.levels_name[level]
        component = record.processName
        _level = self.levels_no.get(level, 0)
        from time import time
        try:
            cmd = self.table.insert().values(TimeKey=time(), Component=component, ServerId=server_id,
                                             Pid=pid, Level=_level, Code=lvl, Message=message,
                                             File=record.filename, Line=record.lineno)
            self.conn.execute(cmd)
        except SQLAlchemyError as e:
            logger.error(f'Error writing to database: {e}')



class ZoneMinder:
    def _init_api(self):
        logger.debug(f"ZoneMinder Session being instantiated with API options: {self.api_opts}")
        self.session = ZMSession(self.api_opts, 'api')

    def _init_db(self):
        logger.debug(f"ZoneMinder Session being instantiated with DB options: {self.db_opts}")
        self.session = ZMSession(self.db_opts, 'db')

    def __init__(self, options: Optional[Dict] = None, force_db: bool = False, force_api: bool = False):
        """Python interface for ZoneMinder. Instantiate and query for information.

         If you do not pass any options, ZoneMinder's DB will be looked for locally by finding zm.conf. If you are on a remote host, you
         must pass options configured for an API connection or a remote DB connection.

        options:
          - host (str): ZoneMinder DB host
          - port (str | int): ZoneMinder port for API or DB (Default 80 for API 3306 for DB)
          - user (str): ZoneMinder API/DB user (If using Authorization)
          - password (str): ZoneMinder API/DB password (If using Authorization)
          - database (str): ZoneMinder DB name
          - driver (str): ZoneMinder database driver (Default "mysql+mysqlconnector")
          - api_url (str): ZoneMinder API URL ("http://zm.EXAMPLE.com/zm/api/") REQUIRED for API
          - portal_url (str): ZoneMinder Portal URL ("http://zm.EXAMPLE.com/zm/")

          - strict_ssl (bool): If False, allows self-signed certificates.
          - conf_path (str): Where the ZM configuration directory is (Also set by PYZM_CONF_PATH environment variable) [Default: /etc/zm]
          - basic_auth (bool): For API session, use basic auth if using auth.

        :param options: (dict) containing options to connect via API or DB.
        :param force_api: (bool) - Force using the API session (REQUIRED: 'host' or 'api_url').
        :param force_db: (bool) - Force using the DB session (REQUIRED: 'host', 'password', 'user', 'database' OR access to zm.conf).
        """

        # ########## MAIN ##########
        if options is None:
            options = {}
        self.options: Optional[Dict] = options
        self.db_opts: Optional[Dict] = None
        self.api_opts: Optional[Dict] = None
        self.Events: list = []
        self.Monitors: list = []
        self.States: list = []
        self.Zones: list = []
        self.Configs: list = []

        self.session: ZMSession
        if self.options is not None:
            self.db_opts = DBOptions(**options)
            self.api_opts = APIOptions(**options)
        logger.debug(f"ZoneMinder-python instantiated with options: {repr(options)}")
        if force_api or force_db:
            if force_api and force_db:
                logger.debug(f"'force_api' and 'force_db' were both passed")
                if (not options) or (options and not options.get('api_url')):
                    logger.debug(f"It seems that options does not have the correct options for API, using SQL session")
                    force_api = False
                    self._init_db()
                elif options and options.get('api_url'):
                    logger.debug(f'It seems that there are the correct options for an API session')
                    self._init_api()
            elif force_api:
                if (not options) or (options and not options.get('api_url')):
                    logger.error(f"'force_api' parameter requires options to be set - A minimum of 'api_url' is required")
                else:
                    self._init_api()
            elif force_db:
                self._init_db()
        else:
            # no force_*
            if (not options) or (options and not options.get('api_url')):
                logger.debug(f'There are the correct options for an SQL session, initializing...')
                self._init_db()
            elif options and options.get('api_url'):
                logger.debug(f'There are the correct options for an API session, initializing...')
                self._init_api()

    def events(self, method=None, options=None) -> List[Optional[ZMEvent]]:
        """Returns a list of events based on filter criteria. Note that each time you call events, a new HTTP call/SQL Query is made.

            options (dict, optional): Various filters that will be applied to events. Defaults to {}.

                        - 'event_id': string # specific event ID to fetch
                        - 'tz': string # long form timezone (example America/New_York),
                        - 'from': string # string # minimum start time (including human-readable
                                       # strings like '1 hour ago' or '10 minutes ago to 5 minutes ago' to create a range)
                        - 'to': string # string # maximum end time
                        - 'mid': int # monitor id
                        - 'min_alarmed_frames': int # minimum alarmed frames
                        - 'max_alarmed_frames': int # maximum alarmed frames
                        - 'object_only': boolean # if True will only pick events that have detected objects

                        # API only options
                        - raw_filter: str # raw url_filter string to use
                        - max_events: int # Maximum number of events to return [Default: 100]
                        - limit: int # alias for max_events


        """
        if method is None:
            method = 'get'
        if options is None:
            options = {}

        if method == 'get':
            events: list = Events(options=options, session=self.session, session_options=self.session.options)
            seen = []
            if events:
                final = ZMEvent()
                for event in events:
                    # API
                    if self.session.type == 'api':
                        event: dict
                        skip = ('StartTime', 'EndTime', 'MaxScoreFrameId', 'FileSystemPath')
                        eid = int(event['Event']['Id'])
                        if eid not in seen:
                            seen.append(eid)

                            # for attr in dir(event):
                            for k, v in event['Event'].items():
                                k: str
                                if k in skip:
                                    continue
                                setattr(final, k, v)
                            self.Events.append(final)
                    # SQL
                    if self.session.type == 'db':
                        event: ZMEvent
                        if event.Id not in seen:
                            seen.append(event.Id)
                            for attr in dir(event):
                                if attr.startswith('__') or attr[0] not in ascii_uppercase:
                                    continue
                                setattr(final, attr, getattr(event, attr))
                            self.Events.append(final)
            return self.Events

    def monitors(self, method=None, options=None) -> Optional[List[Optional[ZMMonitor]]]:
        """Interface with ZoneMinder 'Monitors' Table. 'get' to query, 'set' to manipulate objects.
        Given monitors are fairly static, a cache is maintained instead of querying every time. Use force_reload to force a refresh.

                        - options (dict, optional): Available fields::
                                - 'force_reload': boolean # if True refreshes monitors

                Returns:
                    list of :class:`pyzm.helpers.Monitor`: list of monitors
                    :param options: (dict) OPTIONAL:
                    :param method: (str) 'get' or 'set'
                """
        if options is None:
            options = {}
        if not method:
            method = 'get'

        if method == 'get':
            if options.get("force_reload") or not self.Monitors:
                mons: list = Monitors(session=self.session, session_options=self.session.options)
                final: ZMMonitor = ZMMonitor()
                for mon in mons:
                    if self.session.type == 'api':
                        mon: dict
                        for k, v in mon['Monitor'].items():
                            setattr(final, k, v)

                    elif self.session.type == 'db':
                        mon: ZMMonitor
                        for attr in dir(mon):
                            if attr.startswith('_') or not attr[0].isupper():
                                continue
                            setattr(final, attr, getattr(mon, attr))
                    self.Monitors.append(final)
            return self.Monitors
        elif method == 'set':
            return None
        else:
            raise ValueError("Invalid method: {}".format(method))


    def configs(self, method=None, options=None) -> Optional[List[Optional[ZMConfig]]]:
        """Interface with ZoneMinder 'Configs' Table. 'get' to query, 'set' to manipulate objects."""
        if options is None:
            options = {}
        if not method:
            method = 'get'

        if method == 'get':
            configs: list = Configs(session=self.session, session_options=self.session.options)
            final: ZMConfig = ZMConfig()
            for config in configs:
                if self.session.type == 'api':
                    config: dict
                    for k, v in config['Config'].items():
                        setattr(final, k, v)
                elif self.session.type == 'db':
                    config: ZMConfig
                    for attr in dir(config):
                        if attr.startswith('_') or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(config, attr))
                self.Configs.append(final)
            return self.Configs
        elif method == 'set':
            return None
        else:
            raise ValueError("Invalid method: {}".format(method))

    def zones(self, method=None, options=None) -> Optional[List[Optional[ZMZone]]]:
        """Interface with ZoneMinder 'Zones' Table. 'get' to query, 'set' to manipulate objects."""
        if options is None:
            options = {}
        if not method:
            method = 'get'

        if method == 'get':
            zones: list = Zones(session=self.session, session_options=self.session.options)
            final: ZMZone = ZMZone()
            for zone in zones:
                if self.session.type == 'api':
                    zone: dict
                    for k, v in zone['Zone'].items():
                        setattr(final, k, v)
                elif self.session.type == 'db':
                    zone: ZMZone
                    for attr in dir(zone):
                        if attr.startswith('_') or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(zone, attr))
                self.Zones.append(final)
            return self.Zones
        elif method == 'set':
            return None
        else:
            raise ValueError("Invalid method: {}".format(method))

    def states(self, method=None, options=None) -> Optional[List[Optional[ZMState]]]:
        """Interface with ZoneMinder 'States' Table. 'get' to query, 'set' to manipulate objects."""
        if options is None:
            options = {}
        if not method:
            method = 'get'

        if method == 'get':
            states: list = States(session=self.session, session_options=self.session.options)
            final: ZMState = ZMState()
            for state in states:
                if self.session.type == 'api':
                    state: dict
                    for k, v in state['State'].items():
                        setattr(final, k, v)

                elif self.session.type == 'db':
                    state: ZMState
                    for attr in dir(state):
                        if attr.startswith('_') or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(state, attr))
                self.States.append(final)
            return self.States
        elif method == 'set':
            return None
        else:
            raise ValueError("Invalid method: {}".format(method))
