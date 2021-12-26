import logging

from typing import Optional, Dict, List

from sqlalchemy.exc import SQLAlchemyError

from src.ZMClasses import Events, Monitors, States, Zones, Configs, TriggersX10, Storage, Logs, Servers, Users
from src.ZMSession import ZMSession
from src.dataclasses import ZMEvent, ZMMonitor, ZMState, ZMZone, ZMConfig, ZMTriggersX10, ZMStorage, ZMLogs, ZMServers, \
    ZMUsers
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
        self.TriggersX10: list = []
        self.Storage: list = []
        self.Logs: list = []
        self.Servers: list = []

        self.session: ZMSession
        if self.options is not None:
            self.db_opts = DBOptions(**options)
            self.api_opts = APIOptions(**options)
        logger.debug(f"ZoneMinder-python instantiated with options: {repr(options)}")
        if force_api or force_db:
            if force_api and force_db:
                logger.debug(f"'force_api' and 'force_db' were both passed")
                if (not options) or (options and not options.get('api_url')):
                    logger.debug(f"There are not the correct options for API, using SQL session")
                    force_api = False
                    self._init_db()
                elif options and options.get('api_url'):
                    logger.debug(f'There are the correct options for an API session')
                    self._init_api()
            elif force_api:
                if (not options) or (options and not options.get('api_url')):
                    logger.error(f"'force_api' parameter requires options to be set - A minimum of 'api_url' "
                                 f"is required if you are not using any auth mechanism")
                else:
                    self._init_api()
            elif force_db:
                self._init_db()
        else:
            # no force_*
            if (not options) or (options and not options.get('api_url')):
                logger.debug(f'SQL session, initializing...')
                self._init_db()
            elif options and options.get('api_url'):
                logger.debug(f'API session, initializing...')
                self._init_api()

    def events(self, options=None, method=None) -> List[Optional[ZMEvent]]:
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
            if events:
                for event in events:
                    final = ZMEvent()
                    # API
                    if self.session.type == 'api':
                        event: dict
                        skip = ('StartTime', 'EndTime', 'MaxScoreFrameId', 'FileSystemPath')
                        eid = int(event['Event']['Id'])
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
                        for attr in dir(event):
                            if attr.startswith('_') or not attr[0].isupper():
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
                for mon in mons:
                    # construct a new object on each iteration, otherwise it will just be a long
                    # list of referenced objects
                    final: ZMMonitor = ZMMonitor()
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
        """Interface with ZoneMinder 'Configs' Table. 'get' to query, 'set' to manipulate objects.

        options:
            - id: int - id of config to get
            - name: str - name of config to get
            - category: str - category of config to get
            - type: str - type of config to get

        """
        if options is None:
            options = {}
        if not method:
            method = 'get'

        if method == 'get':
            configs: list = Configs(session=self.session, session_options=self.session.options)
            for config in configs:
                final: ZMConfig = ZMConfig()
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



    def logs(self, method=None, options=None) -> Optional[List[Optional[ZMLogs]]]:
        """Interface with ZoneMinder 'Logs' Table. 'get' to query, 'set' to manipulate objects.

        options: dict - A dict containing filtering options.
            - id: int - filter by id.
            - server_id: int - filter by server id.
            - file: str - calling filename (filename:line_no)
            - component: str - component to filter by.
            - level: int - level to filter by.
            - pid: int - process id.
            - code: str -

            - ascending: bool - sort Time by ascending.
            - descending: bool - sort Time by descending.
            - from: str - filter by start time '20 mins ago' or a range by '1 day ago to 3 hours ago'.
            - to: str - filter by end time '30 mins ago'

        """
        if options is None:
            options = {}
        if not method:
            method = 'get'
        if method == 'get':
            logs: list = Logs(session=self.session, options=options, session_options=self.session.options)
            for log in logs:
                final: ZMLogs = ZMLogs()
                if self.session.type == 'api':
                    log: dict
                    for k, v in log['Logs'].items():
                        setattr(final, k, v)
                elif self.session.type == 'db':
                    log: ZMZone
                    for attr in dir(log):
                        if attr.startswith('_') or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(log, attr))
                self.Logs.append(final)
            return self.Logs
        elif method == 'set':
            return None
        else:
            raise ValueError(f"Invalid method: {method}")


    def servers(self, method=None, options=None) -> Optional[List[Optional[ZMServers]]]:
        """Interface with ZoneMinder 'Servers' Table. 'get' to query, 'set' to manipulate objects."""
        if options is None:
            options = {}
        if not method:
            method = 'get'

        if method == 'get':
            servers: list = Servers(session=self.session, session_options=self.session.options)
            for server in servers:
                final: ZMServers = ZMServers()
                if self.session.type == 'api':
                    server: dict
                    for k, v in server['Server'].items():
                        setattr(final, k, v)
                elif self.session.type == 'db':
                    server: ZMServers
                    for attr in dir(server):
                        if attr.startswith('_') or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(server, attr))
                self.Servers.append(final)
            return self.Servers



    def zones(self, method=None, options=None) -> Optional[List[Optional[ZMZone]]]:
        """Interface with ZoneMinder 'Zones' Table. 'get' to query, 'set' to manipulate objects.

        options:
            - id: int - filter by id.
            - name: str - filter by name.
            - monitor_id: int - filter by monitor_id.
            - type: str - filter by type.


        """
        if options is None:
            options = {}
        if not method:
            method = 'get'

        if method == 'get':
            zones: list = Zones(session=self.session, session_options=self.session.options)
            for zone in zones:
                final: ZMZone = ZMZone()
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

    def storage(self, method=None, options=None) -> Optional[List[Optional[ZMStorage]]]:
        """Interface with ZoneMinder 'Storage' Table. 'get' to query, 'set' to manipulate objects.

        options:
            - id: int - filter by id.
            - name: str - filter by name.
            - path: str - filter by path.
            - server_id: int - filter by server_id.
            - enabled: bool - filter by enabled.
            - used_disk_space: dict {
                - ascending: bool - sort ascending.
                - descending: bool - sort descending.
            } - filter by used disk space.

            """
        if options is None:
            options = {}
        if not method:
            method = 'get'

        if method == 'get':
            storage: list = Storage(session=self.session, options=options, session_options=self.session.options)
            for slices in storage:
                final: ZMStorage = ZMStorage()
                if self.session.type == 'db':
                    slices: ZMStorage
                    for attr in dir(slices):
                        if attr.startswith('_') or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(slices, attr))
                elif self.session.type == 'api':
                    slices: dict
                    for k, v in slices['Storage'].items():
                        setattr(final, k, v)
            self.Storage.append(final)
        return self.Storage


    def triggersx10(self, method=None, options=None):
        """Interface with ZoneMinder 'TriggersX10' Table. 'get' to query, 'set' to manipulate objects."""
        if options is None:
            options = {}
        if not method:
            method = 'get'

        if method == 'get':
            triggers: list = TriggersX10(session=self.session, session_options=self.session.options)
            for trigger in triggers:
                final: ZMTriggersX10 = ZMTriggersX10()
                if self.session.type == 'api':
                    trigger: dict
                    for k, v in trigger['TriggerX10'].items():
                        setattr(final, k, v)
                elif self.session.type == 'db':
                    trigger: ZMTriggersX10
                    for attr in dir(trigger):
                        if attr.startswith('_') or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(trigger, attr))
                self.TriggersX10.append(final)
            return self.TriggersX10
        elif method == 'set':
            return None
        else:
            raise ValueError("Invalid method: {}".format(method))

    def states(self, method=None, options=None) -> Optional[List[Optional[ZMState]]]:
        """Interface with ZoneMinder 'States' Table. 'get' to query, 'set' to manipulate objects
            options:
                id: int - request a state by its id.
                name: str - request a state by name.
                current: bool - return the currently active state.


        """
        if options is None:
            options = {}
        if not method:
            method = 'get'

        if method == 'get':
            states: list = States(session=self.session, options=options, session_options=self.session.options)
            for state in states:
                final: ZMState = ZMState()
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

    def users(self, method=None, options=None) -> Optional[List[Optional[ZMUsers]]]:
        """Interface with ZoneMinder 'Users' Table. 'get' to query, 'set' to manipulate objects
                    options:
                        id: int - filter by Id.
                        name: str - filter by Username.
                        username: str - filter by Username.
                        is_active: bool - filter by 'Enabled' state.
                        api_active: bool - filter by 'APIEnabled' state.
                """
        if options is None:
            options = {}
        if not method:
            method = 'get'

        if method == 'get':
            states: list = Users(session=self.session, options=options)
            for state in states:
                final: ZMState = ZMUsers()
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
            raise ValueError(f"Invalid method: {method}")