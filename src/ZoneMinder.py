import logging
import warnings
from datetime import datetime
from string import ascii_uppercase
from typing import Optional, Dict, List, Any, Union

import dateparser as dateparser
import sqlalchemy.orm
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Query

import src.dataclasses
from src.ZMSession import ZMSession
from src.dataclasses import ZMEvent
from src.models import DBOptions, APIOptions

logger = logging.getLogger('ZM')
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_fmt = logging.Formatter(
    '%(asctime)s %(name)s[%(process)s]  %(levelname)s %(filename)s:%(lineno)d->[%(message)s]')
console_handler.setFormatter(console_fmt)
logger.addHandler(console_handler)


def str2bool(v: Optional[Union[str, bool]]) -> Optional[Union[str, bool]]:
    """Turns a string into a boolean"""
    if v is None:
        return False
    if isinstance(v, bool):
        return v
    v = str(v)
    true_ret = ("yes", "true", "t", "y", "1", "on", "ok", "okay")
    false_ret = ("no", "false", "f", "n", "0", "off")
    if v.lower() in true_ret:
        return True
    elif v.lower() in false_ret:
        return False
    else:
        logger.error(
            f"str2bool: '{v}' is not able to be parsed into a boolean operator"
        )
        return


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
        self.Events = []
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

    def get_events(self, options=None) -> List[Optional[ZMEvent]]:
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
        if options is None:
            options = {}
        events: list = Events(options=options, session=self.session, session_options=self.session.options).work()
        seen = []
        if events:
            final = ZMEvent()
            for event in events:
                if self.session.type == 'api':
                    event: dict
                    skip = ('StartTime', 'EndTime', 'MaxScoreFrameId', 'FileSystemPath')
                    # int_ = ('Id', 'MonitorId', 'StorageId', 'SecondaryStorageId', 'Width', 'Height', 'Frames'
                    #         'AlarmFrames', 'SaveJPEGs', 'TotScore', 'AvgScore', 'MaxScore', 'Archived', 'Videoed',
                    #         'Uploaded', 'Emailed', 'Messaged', 'Executed', 'StateId', 'DiskSpace', 'MaxScoreFrameId')
                    eid = int(event['Event']['Id'])
                    if eid not in seen:
                        seen.append(eid)

                        # for attr in dir(event):
                        for k, v in event['Event'].items():
                            k: str
                            if k in skip:
                                continue
                            # elif k == 'Length':
                            #     v = float(v)
                            # elif k.endswith('DateTime'):
                            #     v = datetime.strptime(v, '%Y-%m-%d %H:%M:%S')

                            setattr(final, k, v)
                        self.Events.append(final)


                if self.session.type == 'db':
                    if event.Id not in seen:
                        seen.append(event.Id)
                        for attr in dir(event):
                            if attr.startswith('__') or attr[0] not in ascii_uppercase:
                                continue
                            setattr(final, attr, getattr(event, attr))
                        self.Events.append(final)
        return self.Events


class Monitors:
    def __init__(
            self,
            options: Optional[Dict] = None,
            session: ZMSession = None,
            session_options: Optional[Union[DBOptions, APIOptions]] = None,
    ):
        """Returns list of monitors. Given monitors are fairly static, maintains a cache and returns from cache on subsequent calls.

                    Args:
                        options (dict, optional): Available fields::

                            {
                                'force_reload': boolean # if True refreshes monitors

                            }

                Returns:
                    list of :class:`pyzm.helpers.Monitor`: list of monitors
                """
        if options is None:
            options = {}
        if options.get("force_reload") or not self.Monitors:
            self.Monitors = Monitors()
        return self.Monitors


class Monitors:






class Events:
    def __init__(
            self,
            options: Optional[Dict] = None,
            session: ZMSession = None,
            session_options: Optional[Union[DBOptions, APIOptions]] = None,
            no_warn = False,
    ):
        """
        Used internally to process Events

        session (ZMSession) - API/SQL session used to query available events.
        no_warn (Boolean) - Turn the Python warning off. Warning is logged regardless, this turns off internal Python warning.

            options:
              - event_id: string # specific event ID to fetch
              - tz: string # long form timezone (example America/New_York),
              - from: string #  minimum start time (including human-readable
                                 # strings like '1 hour ago' or '10 minutes ago to 5 minutes ago' to create a range)
              - to: string # string # maximum end time
              - mid: int # monitor id
              - min_alarmed_frames: int # minimum alarmed frames
              - max_alarmed_frames: int # maximum alarmed frames
              - object_only: boolean # if True will only pick events that have detected objects

              # API only options
              - raw_filter: str # raw url_filter string to use
              - max_events: int # Maximum number of events to return [Default: 100]
              - limit: int # alias for max_events

        """
        self.session_options: Union[DBOptions, APIOptions] = session_options
        self.options: Optional[Dict] = options
        if self.options.get('object_only') is not None:
            self.options['object_only'] = str2bool(self.options['object_only'])

        self.session: ZMSession = session
        self.events = []
        if not self.options:
            msg = f"No filters passed to <Events> via the 'options' parameter, grabbing ALL events... If this is " \
                  f"unintended, use a filter via 'options'."
            if not no_warn:
                msg = f"{msg} To turn this warning off pass 'True' to the no_warn parameter."
                warnings.warn(msg)
            # Log the warning regardless
            logger.warning(msg=msg)

    def __iter__(self):
        if self.events:
            for event in self.events:
                yield event

    def __repr__(self):
        handler: str
        if self.session.type == 'db':
            handler = 'SQL'
        else:
            handler = 'API'
        ret = f"<ZoneMinder Events Count:{len(self.events)} Handler:{handler}>"

    def work(self):
        raw_data: Any
        # Database
        options = self.options
        if self.session and self.session.type == 'db':
            from sqlalchemy.sql.expression import and_
            logger.debug(f"Retrieving events via SQL using options: {options}")
            eid: Optional[str] = options.get('event_id')
            tz: Optional[Union[str, dict]] = options.get('tz')
            db_tz: dict = {}
            raw_data: Query
            # query() is generative, can keep .where() and filter()'ing
            session: Optional[sqlalchemy.orm.Session] = None
            try:
                session = self.session.db_sess()
                events: src.dataclasses.ZMEvent = self.session.db.Events
                # events = self.session.auto_map.classes.Events
                raw_data = session.query(events)

                if eid:
                    logger.debug(f"Using EventId to filter SQL")
                    raw_data = raw_data.filter(events.Id == eid)
                if tz:
                    db_tz = {'TIMEZONE': tz}
                    logger.debug(f'Converting to TimeZone: {tz}')

                if options.get('from'):
                    logger.debug(f"Using StartDateTime to filter SQL")
                    from_list = options.get('from').split(" to ", 1)
                    if len(from_list) == 2:
                        from_start = dateparser.parse(from_list[0], settings=db_tz)
                        from_end = dateparser.parse(from_list[1], settings=db_tz)
                        if from_start > from_end:
                            from_start, from_end = from_end, from_start
                        logger.debug("StartDateTime has 'to' in the 'from' option, querying with a range")
                        raw_data = raw_data.filter(and_(events.StartDateTime >= from_start,
                                                        events.StartDateTime <= from_end))
                    else:
                        raw_data = raw_data.filter(events.StartDateTime >= dateparser.parse(from_list[0], settings=db_tz))

                if options.get('to'):
                    logger.debug(f"Using EndDateTime to filter SQL")
                    to_list = options.get('to').split(" to ", 1)
                    if len(to_list) == 2:
                        to_start = dateparser.parse(to_list[0], settings=db_tz)
                        to_end = dateparser.parse(to_list[1], settings=db_tz)
                        if to_start > to_end:
                            to_start, to_end = to_end, to_start
                        raw_data = raw_data.filter(and_(events.EndDateTime >= to_start,
                                                        events.EndDateTime <= to_end))
                    else:
                        raw_data = raw_data.filter(
                            events.EndDateTime >= dateparser.parse(to_list[0], settings=db_tz))

                if options.get('mid'):
                    logger.debug(f'Using MonitorId to filter SQL')
                    raw_data = raw_data.filter(events.MonitorId == options.get('mid'))
                if options.get('min_alarmed_frames'):
                    logger.debug(f"Using minimum AlarmFrames to filter SQL")
                    raw_data = raw_data.filter(events.AlarmFrames >= options.get('min_alarmed_frames'))
                if options.get('max_alarmed_frames'):
                    logger.debug(f"Using maximum AlarmFrames to filter SQL")
                    raw_data = raw_data.filter(events.AlarmFrames <= options.get('max_alarmed_frames'))
                if options.get('object_only'):
                    logger.debug(f"Using detected objects to filter SQL")
                    # MySQL/MariaDB regexp, Postgres would be op('~')
                    raw_data = raw_data.filter(events.Notes.op('regexp')(r'.*:detected:.*'))
                events = raw_data.all()  # return a list of matches
            except Exception as exc:
                logger.exception(f"Error querying DB for 'Events': {exc}", exc_info=True)
            else:
                return events
            finally:
                # Always close the session when not using a context manager
                if session:
                    logger.debug(f"Closing DB session after querying for events")
                    session.close()
                    logger.debug(f"DB Session closed!")

        # API
        elif self.session and self.session.type == 'api':
            if options is None:
                logger.error("No options provided, cannot retrieve events")
                return
            logger.info('Retrieving events via API')
            url_filter = ''
            tz = {}

            if options.get('event_id'):
                url_filter += f"/Id=:{options.get('event_id')}"
            if options.get('tz'):
                tz = {'TIMEZONE': options.get('tz')}
                logger.debug(f'Using TZ: {tz}')
            if options.get('from'):
                from_list = options.get('from').split(" to ", 1)
                if len(from_list) == 2:
                    from_start = dateparser.parse(from_list[0], settings=tz)
                    from_end = dateparser.parse(from_list[1], settings=tz)
                    if from_start > from_end:
                        from_start, from_end = from_end, from_start

                    url_filter += "/StartTime >=:" + from_start.strftime('%Y-%m-%d %H:%M:%S')
                    url_filter += "/StartTime <=:" + from_end.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    url_filter += "/StartTime >=:" + dateparser.parse(from_list[0], settings=tz).strftime(
                        '%Y-%m-%d %H:%M:%S')
            if options.get('to'):
                to_list = options.get('to').split(" to ", 1)
                if len(to_list) == 2:
                    to_start = dateparser.parse(to_list[0], settings=tz)
                    to_end = dateparser.parse(to_list[1], settings=tz)
                    if to_start > to_end:
                        to_start, to_end = to_end, to_start
                    url_filter += "/EndTime <=:" + to_end.strftime('%Y-%m-%d %H:%M:%S')
                    url_filter += "/EndTime >=:" + to_start.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    url_filter += "/EndTime <=:" + dateparser.parse(to_list[0], settings=tz).strftime(
                        '%Y-%m-%d %H:%M:%S')
            if options.get('mid'):
                url_filter += "/MonitorId =:" + str(options.get('mid'))
            if options.get('min_alarmed_frames'):
                url_filter += "/AlarmFrames >=:" + str(options.get('min_alarmed_frames'))
            if options.get('max_alarmed_frames'):
                url_filter += "/AlarmFrames <=:" + str(options.get('max_alarmed_frames'))
            if options.get('object_only'):
                # 'detected' is the key for grabbing notes from DB and the zm_event_start/end wrappers
                url_filter += "/Notes REGEXP:detected:"

            # catch all
            if options.get('raw_filter'):
                url_filter += options.get('raw_filter')
            # print ('URL filter: ',url_filter)
            # todo - no need for url_prefix in options
            url_prefix = f'{self.session_options.api_url}/events/index'

            url = f'{url_prefix}{url_filter}.json'
            params = {
                'sort': 'StartTime',
                'direction': 'desc',
                'page': 1
            }
            for k in options:
                if k in params:
                    params[k] = options[k]

            num_events = 100
            if options.get('max_events'):
                num_events = options.get('max_events')
            if options.get('limit'):
                num_events = options.get('limit')

            params['limit'] = num_events
            curr_events = 0
            self.events = []
            while True:
                try:
                    # r = self.session.api_sess.get(url=url, params=params)
                    r = self.session.api_sess.make_request(url=url, query=params)
                except Exception as ex:
                    logger.error(f"Events: error making request for events -> {url}")
                    raise ex
                else:
                    self.events.extend(r.get('events'))
                    pagination = r.get('pagination')
                    if not pagination or not pagination.get('nextPage'):
                        break
                    curr_events += int(pagination.get('current'))
                    if curr_events >= num_events:
                        logger.debug(f"get_events:API: Hit 'Events' limit/max_events ({num_events})")
                        break
                    params['page'] += 1
            return self.events
