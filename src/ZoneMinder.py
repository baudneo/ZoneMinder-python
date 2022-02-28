import logging
from dataclasses import fields
from enum import Enum

from typing import Optional, Dict, List, Union

from sqlalchemy.exc import SQLAlchemyError

from src.ZMClasses import (
    Events,
    Monitors,
    States,
    Zones,
    Configs,
    TriggersX10,
    Storage,
    Logs,
    Servers,
    Users,
    Groups,
)
from src.ZMSession import ZMSession
from src.dataclasses import (
    ZMEvent,
    ZMMonitor,
    ZMState,
    ZMZone,
    ZMConfig,
    ZMOptions,
    ZMTriggersX10,
    ZMStorage,
    ZMLogs,
    ZMServers,
    ZMUsers,
    InterfacePrivs,
    DBOptions,
    APIOptions,
    ZMGroups,
)

logger = logging.getLogger("ZM")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_fmt = logging.Formatter(
    "%(asctime)s %(name)s[%(process)s]  %(levelname)s %(filename)s:%(lineno)d->[%(message)s]"
)
console_handler.setFormatter(console_fmt)
logger.addHandler(console_handler)

ZM_AUTH: bool = False

class ZoneMinder:
    def _init_api(self):
        logger.debug(
            f"ZoneMinder Session being instantiated with API options: {self.api_opts}"
        )
        self.session = ZMSession(self.api_opts, "api")

    def _init_db(self):
        logger.debug(
            f"ZoneMinder Session being instantiated with DB options: {self.db_opts}"
        )
        self.session = ZMSession(self.db_opts, "db")
        # Check if ZM_OPT_USE_AUTH is enabled, calling this by itsefl will populate self.Configs
        zm_opt_auth: Configs = self.configs(method='get', options={'name': 'ZM_OPT_USE_AUTH', 'value': '0'})
        if zm_opt_auth and zm_opt_auth[0].Value != 1:
            global ZM_AUTH
            ZM_AUTH = True
        logger.info(f"ZM_OPT_USE_AUTH: {ZM_AUTH}")
        if ZM_AUTH:
            logger.debug(f"ZM_OPT_USE_AUTH is enabled!")
            self.authorize(self.db_opts.zmuser, self.db_opts.zmpassword)
        else:
            logger.debug(f"ZM_OPT_USE_AUTH is disabled!")
            self.authorized = None

    def __init__(
        self,
        options: Optional[Dict] = None,
        force_db: bool = False,
        force_api: bool = False,
    ):
        """Python interface for ZoneMinder. Instantiate and query for information.

         If you do not pass any options, ZoneMinder's DB will be looked for locally by finding zm.conf. If you are on a remote host, you
         must pass options configured for an API connection or a remote DB connection.

        options:
          - host (str): ZoneMinder DB host.
          - port (str | int): ZoneMinder port for API or DB (Default 80 for API 3306 for DB).
          - user (str): DB connection user.
          - password (str): DB connection password.
          - zmuser (str): ZoneMinder 'Users' Username.
          - zmpassword (str): ZoneMinder 'Users' Password.
          - database (str): ZoneMinder DB name (default 'zm').
          - driver (str): ZoneMinder database driver (Default "mysql+mysqlconnector").
          - api_url (str): ZoneMinder API URL ("http://zm.EXAMPLE.com/zm/api/") REQUIRED for API.
          - portal_url (str): ZoneMinder Portal URL ("http://zm.EXAMPLE.com/zm/").

          - strict_ssl (bool): If False, allows self-signed certificates.
          - conf_path (str): Where the ZM configuration directory is (Also set by PYZM_CONF_PATH environment variable) [Default: /etc/zm]
          - basic_auth (bool): For API session, use basic auth if using auth.

        :param options: (dict) containing options to connect via API or DB.
        :param force_api: (bool) - Force using the API session (REQUIRED: 'host' or 'api_url').
        :param force_db: (bool) - Force using the DB session (REQUIRED: 'host', 'password', 'user', 'database' OR access to zm.conf).
        """

        # ########## MAIN ##########
        if options is None or (
            options and (not options.get("zmuser") or not options.get("zmpassword"))
        ):
            logger.info(
                f"You have not included a username and password to authorize yourself to the Zoneminder "
                f"interface. There will be very limited access to the available data"
            )
            options = {} if options is None else options
        from os import getenv

        if not options.get("zmuser"):
            options["user"] = getenv("PYZM_USER")
        if not options.get("zmpassword"):
            options["password"] = getenv("PYZM_PASSWORD")

        self.options: Optional[Dict] = options
        self.db_opts: Optional[Dict] = None
        self.api_opts: Optional[Dict] = None
        self.Events: list = []
        self.Monitors: list = []
        self.States: list = []
        self.Zones: list = []
        self.Configs: list = []
        self.Options: list = []
        self.TriggersX10: list = []
        self.Storage: list = []
        self.Logs: list = []
        self.Servers: list = []
        self.Users: list = []
        self.Groups: list = []

        # Local DB user authentication, this is the ZM 'Users' mechanism that
        # controls access to view/edit on different types of data, need to research the Perl module in order to get the
        # proper permission scheme here.
        self.user: str = options.get("zmuser")
        self.password: str = options.get("zmpassword")
        self.zm_auth_enabled: bool = False
        self.authorized: bool = False
        self.auth_privileges: Optional[InterfacePrivs] = None

        self.session: ZMSession
        logger.debug(f"ZoneMinder-python instantiated with options: {repr(options)}")
        if self.options is not None:
            # dataclass hack to avoid TypeError: unknown key Exceptions
            self.db_opts = DBOptions(
                **{
                    k: v
                    for k, v in options.items()
                    if k in set(f.name for f in fields(DBOptions))
                }
            )
            if (not options.get("user")) and options.get("zmuser"):
                options["user"] = options["zmuser"]
            if (not options.get("password")) and options.get("zmpassword"):
                options["password"] = options["zmpassword"]
            self.api_opts = APIOptions(
                **{
                    k: v
                    for k, v in options.items()
                    if k in set(f.name for f in fields(APIOptions))
                }
            )
        if force_api or force_db:
            if force_api and force_db:
                logger.debug(f"'force_api' and 'force_db' were both passed")
                if (not options) or (options and not options.get("api_url")):
                    logger.debug(
                        f"There are not the correct options for API, using SQL session"
                    )
                    force_api = False
                    self._init_db()
                elif options and options.get("api_url"):
                    logger.debug(f"There are the correct options for an API session")
                    self._init_api()
            elif force_api:
                if (not options) or (options and not options.get("api_url")):
                    logger.error(
                        f"'force_api' parameter requires options to be set - A minimum of 'api_url' "
                        f"is required if you are not using any auth mechanism"
                    )
                    raise SyntaxError("A minimum of 'api_url' is required")
                else:
                    self._init_api()
            elif force_db:
                self._init_db()
        else:
            # no force_*
            if (not options) or (options and not options.get("api_url")):
                logger.debug(f"SQL session, initializing...")
                self._init_db()
            elif options and options.get("api_url"):
                logger.debug(f"API session, initializing...")
                self._init_api()

    def authorize(self, username: str, password: str) -> None:
        """Internal use when using DB to compare supplied password with hashed password and retrieve permissions

        :param username: (str) ZoneMinder username
        :param password: (str) ZoneMinder password
        """
        if not username or not password:
            self.authorized = False
            logger.warning(f"No username or password supplied")
            return
        options = {
            "username": username,
            "enabled": True,
        }

        users: List[ZMUsers] = Users(session=self.session, options=options)
        # Should only be 1 user but iterate it anyway
        import bcrypt

        existing: str = ""
        for user in users:
            user: ZMUsers
            if user.Password:
                if bcrypt.checkpw(
                    password.encode("utf-8"), user.Password.encode("utf-8")
                ):
                    self.authorized = True
                    self.auth_privileges = InterfacePrivs(
                        Stream=user.Stream,
                        Events=user.Events,
                        Monitors=user.Monitors,
                        System=user.System,
                        Control=user.Control,
                        Snapshots=user.Snapshots,
                        Devices=user.Devices,
                        Groups=user.Groups,
                    )
                    logger.debug(
                        f"Successful authorization for user {user.Username} - Privileges: {self.auth_privileges}"
                    )
                    break
            logger.warning(f"Failed authorization for user: {user.Username}")
            self.authorized = False

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

                    - max_events: int # Maximum number of events to return [Default for API: 100]
                    - limit: int # alias for max_events

                    # API only options
                    - raw_filter: str # raw url_filter string to use



        """
        # Add auth / permission checks here

        if method is None:
            method = "get"
        if options is None:
            options = {}
        self.options = options
        if method == "get":
            if self.session.type == "db":
                if not self.authorized:
                    logger.error(f"You must be authorized to view/edit 'Events'!")
                    return []
                if self.auth_privileges.Events == "None":
                    logger.error(
                        f"To access 'Events' user {self.user} must have a minimum of 'View' permissions for "
                        f"'Events'. The current level is {self.auth_privileges.Events}"
                    )
                    return []

            events: list = Events(
                options=options,
                session=self.session,
                session_options=self.session.options,
            )
            if events:
                for event in events:
                    final = ZMEvent()
                    # API
                    if self.session.type == "api":
                        event: dict
                        skip = (
                            "StartTime",
                            "EndTime",
                            "MaxScoreFrameId",
                            "FileSystemPath",
                        )
                        eid = int(event["Event"]["Id"])
                        # for attr in dir(event):
                        for k, v in event["Event"].items():
                            k: str
                            if k in skip:
                                continue
                            setattr(final, k, v)
                        self.Events.append(final)
                    # SQL
                    if self.session.type == "db":
                        event: ZMEvent
                        for attr in dir(event):
                            if attr.startswith("_") or not attr[0].isupper():
                                continue
                            setattr(final, attr, getattr(event, attr))
                        self.Events.append(final)
            return self.Events

    def monitors(
        self, method=None, options=None
    ) -> Optional[List[Optional[ZMMonitor]]]:
        """Interface with ZoneMinder 'Monitors' Table. 'get' to query, 'set' to manipulate objects.
        Given monitors are fairly static, a cache is maintained instead of querying every time. Use force_reload to force a refresh.

                        - options (dict, optional): Available fields::
                                - 'id': string # specific monitor id to fetch
                                - 'name': string # specific monitor name to fetch
                                - 'enabled': boolean # if True will only pick enabled monitors

                                - 'force_reload': boolean # if True refreshes monitors

                Returns:
                    list of :class:`pyzm.helpers.Monitor`: list of monitors
                    :param options: (dict) OPTIONAL:
                    :param method: (str) 'get' or 'set'
        """

        if options is None:
            options = {}
        self.options = options
        if not method:
            method = "get"

        if method == "get":
            if self.session.type == "db":
                restricted = self.auth_privileges.Monitors.split(",")
                if not self.authorized:
                    logger.error(f"You must be authorized to view/edit 'Monitors'!")
                    return
                if (
                    self.auth_privileges.Monitors != "View"
                    or self.auth_privileges.Monitors != "Edit"
                ):
                    logger.error(
                        f"To access 'Monitors' user {self.user} must have a minimum of 'View' permissions for "
                        f"'Monitors'. The current level is {self.auth_privileges.Monitors}"
                    )
                    return
                if str(self.options.get("id")) in restricted:
                    logger.error(
                        f"Monitor {self.options.get('Id')} is in the restricted Id's for user {self.user}"
                        f" - UNAUTHORIZED!"
                    )
                    return

            if options.get("force_reload") or not self.Monitors:
                mons: List[Union[ZMMonitor, Dict[str, str]]] = Monitors(
                    session=self.session, session_options=self.session.options
                )
                for mon in mons:
                    final: ZMMonitor = ZMMonitor()
                    if self.session.type == "api":
                        mon: dict
                        for k, v in mon["Monitor"].items():
                            setattr(final, k, v)

                    elif self.session.type == "db":
                        mon: ZMMonitor
                        if str(mon.Id) not in restricted:
                            for attr in dir(mon):
                                if attr.startswith("_") or not attr[0].isupper():
                                    continue
                                setattr(final, attr, getattr(mon, attr))
                        else:
                            logger.debug(
                                f"Monitor {mon.Id} is in the restricted Id's ({restricted}) "
                                f"for user {self.user}, skipping..."
                            )
                            final = None
                    self.Monitors.append(final) if final else None
            return self.Monitors
        elif method == "set":
            return None
        else:
            raise ValueError("Invalid method: {}".format(method))

    def configs(self, method=None, options=None) -> Optional[List[Optional[ZMConfig]]]:
        """Interface with ZoneMinder 'Configs' Table. 'get' to query, 'set' to manipulate objects.

        When using the DB interface to 'set' Configs, you must log in using a Username/Password configured in ZoneMinder
         'Users', also your user must have the correct permissions and 'restricted monitors' may affect what Configs
         can be changed. The 'id' or 'name' AND 'value' fields are required for setting as well.

        options:
            - id: int - id of config to get
            - name: str - EXACT name of config to get
            - name_contains: str - name of config to get, name must contain this string
            - category: str - category of config to get
            - type: str - type of config to get
            - value: str - value to set the config (Required when method = 'set')

        """
        if options is None:
            options = {}
        self.options = options

        if not method:
            method = "get"

        if method == "get":
            # if self.session.type == "db":
            #     if not self.authorized:
            #         logger.error(f"You must be authorized to view/edit 'Configs'!")
            #         return
            #     if self.auth_privileges.System == "None":
            #         logger.error(
            #             f"To access 'Configs' user {self.user} must have a minimum of 'View' permissions for "
            #             f"'System'. The current level is {self.auth_privileges.System}"
            #         )
            #         return

            configs: list = Configs(
                session=self.session,
                session_options=self.session.options,
                options=self.options,
            )
            for config in configs:
                final: ZMConfig = ZMConfig()
                if self.session.type == "api":
                    config: dict
                    for k, v in config["Config"].items():
                        setattr(final, k, v)
                elif self.session.type == "db":
                    config: ZMConfig
                    for attr in dir(config):
                        if attr.startswith("_") or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(config, attr))
                self.Configs.append(final)
            # self.Configs = self.Configs.sort(key=lambda x: x.Id)
            # self.Configs = sorted(self.Configs, key=lambda x: x.Id)
            return self.Configs

        elif method == "set":
            if self.session.type == "db":
                if not self.authorized:
                    logger.error(f"You must be authorized to view/edit 'Configs'!")
                    return
                if self.auth_privileges.System != "Edit":
                    logger.error(
                        f"To edit 'Configs' user {self.user} must have a minimum of 'Edit' permissions for "
                        f"'System'. The current level is {self.auth_privileges.System}"
                    )
                    return
            configs: List[ZMConfig] = self.configs(method="get", options=self.options)
            if self.session.type == "db":
                pass

            if self.session.type == "api":
                target = ""
                config_obj = None
                if not options.get("value"):
                    logger.error("You must provide a value to set the config!")
                    return
                if not options.get("id") and not options.get("name"):
                    logger.error("You must provide an id or name to set the config!")
                    return
                if options.get("id") and not options.get("name"):
                    logger.debug(f"Searching for config with id {options.get('id')}")
                    for config in configs:
                        if config.get("Id") == options.get("id"):
                            target = config.get("Name")
                            logger.debug(
                                f"Found config with id {options.get('id')}, NAME={target}"
                            )
                            config_obj = config
                            break
                if options.get("name"):
                    target = options.get("name")
                url = f"{self.api_opts.api_url}/configs/edit/{target}.json"
                params = {
                    "Config[Value]": options.get("value"),
                }
                try:
                    r = self.session.api_sess.make_request(
                        url, payload=params, type_action="put"
                    )
                except Exception as e:
                    logger.error(f"Failed to set config: {e}")
                    return
                if r.status_code == 200:
                    logger.info(
                        f"Successfully set config '{target}' to '{options.get('value')}'"
                    )
                    return

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
        self.options = options

        if not method:
            method = "get"
        if method == "get":
            logs: list = Logs(
                session=self.session,
                options=options,
                session_options=self.session.options,
            )
            for log in logs:
                final: ZMLogs = ZMLogs()
                if self.session.type == "api":
                    log: dict
                    for k, v in log["Log"].items():
                        setattr(final, k, v)
                elif self.session.type == "db":
                    log: ZMZone
                    for attr in dir(log):
                        if attr.startswith("_") or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(log, attr))
                self.Logs.append(final)
            return self.Logs
        elif method == "set":
            return None
        else:
            raise ValueError(f"Invalid method: {method}")

    def groups(self, method=None, options=None) -> Optional[List[Optional[ZMGroups]]]:
        """Interface with ZoneMinder 'Groups' Table. 'get' to query, 'set' to manipulate objects.

        options: dict - A dict containing filtering options.
            - id: int - filter by id.
            - name: str - filter by name.
            - parent_id: int - filter by parent id.

        :param dict options: A dict containing filtering options.
        :param str method: The method to use, one of 'set' or 'get'.
        :return: List[Optional[ZMGroups]]
        :raises ValueError: If method is not 'get' or 'set'.
        :raises NotImplementedError: If method is 'set'.
        """
        if options is None:
            options = {}
        self.options = options
        if not method:
            method = "get"
        if method == "get":
            groups: list = Groups(
                session=self.session, session_options=self.session.options
            )
        elif method == "set":
            raise NotImplementedError("'set' not implemented yet.")
        else:
            raise ValueError(f"Invalid method: {method}")

    def servers(
        self, method: Optional[str] = None, options: Optional[Dict] = None
    ) -> Optional[List[Optional[ZMServers]]]:
        """Interface with ZoneMinder 'Servers' Table. 'get' to query, 'set' to manipulate objects.
        :param method: one of 'get' or 'set'.
        :param dict options: A dict containing filtering options.
        """
        if options is None:
            options = {}
        self.options = options

        if not method:
            method = "get"

        if method == "get":
            servers: list = Servers(
                session=self.session, session_options=self.session.options
            )
            for server in servers:
                final: ZMServers = ZMServers()
                if self.session.type == "api":
                    server: dict
                    for k, v in server["Group"].items():
                        setattr(final, k, v)
                elif self.session.type == "db":
                    server: ZMServers
                    for attr in dir(server):
                        if attr.startswith("_") or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(server, attr))
                self.Groups.append(final)
            return self.Groups

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
        self.options = options

        if not method:
            method = "get"

        if method == "get":
            if self.session.type == "db":
                restricted = self.auth_privileges.Monitors.split(",")
                if not self.authorized:
                    logger.error(f"You must be authorized to view/edit 'Zones'!")
                    return
                if self.auth_privileges.Monitors == "None":
                    logger.error(
                        f"To access 'Zones' user {self.user} must have a minimum of 'View' permissions for "
                        f"'Monitors'. The current level is {self.auth_privileges.Monitors}"
                    )
                    return
                if self.options.get("id") in restricted:
                    logger.debug(
                        f"Monitor Id: {self.options.get('id')} is restricted for user {self.user}"
                    )
                    return
            zones: list = Zones(
                session=self.session, session_options=self.session.options
            )
            for zone in zones:
                final: ZMZone = ZMZone()
                if self.session.type == "api":
                    zone: dict
                    for k, v in zone["Zone"].items():
                        setattr(final, k, v)
                elif self.session.type == "db":
                    zone: ZMZone
                    if zone.MonitorId in restricted:
                        logger.debug(
                            f"Monitor Id: {zone.MonitorId} is restricted for user {self.user}, skipping..."
                        )
                        continue
                    for attr in dir(zone):
                        if attr.startswith("_") or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(zone, attr))
                self.Zones.append(final)
            return self.Zones
        elif method == "set":
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
        self.options = options

        if not method:
            method = "get"

        if method == "get":
            if self.session.type == "db":
                if not self.authorized:
                    logger.error(f"You must be authorized to view/edit 'Storage'!")
                    return
                if (
                    self.auth_privileges.System != "View"
                    and self.auth_privileges.System != "Edit"
                ):
                    logger.error(
                        f"To access 'Storage' user {self.user} must have a minimum of 'View' permissions for "
                        f"'System'. The current level is {self.auth_privileges.System}"
                    )
                    return
            storage: list = Storage(
                session=self.session,
                options=options,
                session_options=self.session.options,
            )
            for slices in storage:
                final: ZMStorage = ZMStorage()
                if self.session.type == "db":
                    slices: ZMStorage
                    for attr in dir(slices):
                        if attr.startswith("_") or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(slices, attr))
                elif self.session.type == "api":
                    slices: dict
                    for k, v in slices["Storage"].items():
                        setattr(final, k, v)
            self.Storage.append(final)
        return self.Storage

    def triggersx10(self, method=None, options=None):
        """Interface with ZoneMinder 'TriggersX10' Table. 'get' to query, 'set' to manipulate objects."""
        if options is None:
            options = {}
        self.options = options

        if not method:
            method = "get"

        if method == "get":
            if self.session.type == "db":
                if not self.authorized:
                    logger.error(f"You must be authorized to view/edit 'TriggersX10'!")
                    return
                if self.auth_privileges.System == "None":
                    logger.error(
                        f"To access 'TriggersX10' user {self.user} must have a minimum of 'View' permissions "
                        f"for 'System'. The current level is {self.auth_privileges.System}"
                    )
                    return
            triggers: list = TriggersX10(
                session=self.session, session_options=self.session.options
            )
            for trigger in triggers:
                final: ZMTriggersX10 = ZMTriggersX10()
                if self.session.type == "api":
                    trigger: dict
                    for k, v in trigger["TriggerX10"].items():
                        setattr(final, k, v)
                elif self.session.type == "db":
                    trigger: ZMTriggersX10
                    for attr in dir(trigger):
                        if attr.startswith("_") or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(trigger, attr))
                self.TriggersX10.append(final)
            return self.TriggersX10
        elif method == "set":
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
        self.options = options

        if not method:
            method = "get"

        if method == "get":
            if self.session.type == "db":
                if not self.authorized:
                    logger.error(f"You must be authorized to view/edit 'States'!")
                    return
                if self.auth_privileges.System == "None":
                    logger.error(
                        f"To access 'States' user {self.user} must have a minimum of 'View' permissions for "
                        f"'System'. The current level is {self.auth_privileges.System}"
                    )
                    return

            states: list = States(
                session=self.session,
                options=options,
                session_options=self.session.options,
            )
            for state in states:
                final: ZMState = ZMState()
                if self.session.type == "api":
                    state: dict
                    for k, v in state["State"].items():
                        setattr(final, k, v)

                elif self.session.type == "db":
                    state: ZMState
                    for attr in dir(state):
                        if attr.startswith("_") or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(state, attr))
                self.States.append(final)
            return self.States
        elif method == "set":
            return None
        else:
            raise ValueError("Invalid method: {}".format(method))

    def users(self, method=None, options=None) -> Optional[List[Optional[ZMUsers]]]:
        """Interface with ZoneMinder 'Users' Table. 'get' to query, 'set' to manipulate objects
        options:
            id: int - filter by Id.
            name: str - filter by Username.
            username: str - filter by Username.
            enabled: bool - filter by 'Enabled' state.
            api_active: bool - filter by 'APIEnabled' state.
        """

        if options is None:
            options = {}
        self.options = options

        if not method:
            method = "get"

        if method == "get":
            if self.session.type == "db":
                if not self.authorized:
                    logger.error(f"You must authorize yourself to the DB interface")
                    return
                if self.auth_privileges.System == "None":
                    logger.error(
                        f"To access 'Users' user {self.user} must have a minimum of 'View' permissions for "
                        f"'System'. The current level is {self.auth_privileges.System}"
                    )
                    return
            users: list = Users(
                session=self.session,
                options=options,
                session_options=self.session.options,
            )
            for user in users:
                final: ZMUsers = ZMUsers()
                if self.session.type == "api":
                    user: dict
                    for k, v in user["User"].items():
                        setattr(final, k, v)

                elif self.session.type == "db":
                    user: ZMUsers
                    for attr in dir(user):
                        if attr.startswith("_") or not attr[0].isupper():
                            continue
                        setattr(final, attr, getattr(user, attr))

                self.Users.append(final)
            return self.Users
        elif method == "set":
            return None
        else:
            raise ValueError(f"Invalid method: {method}")
