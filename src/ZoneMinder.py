import warnings
from typing import Optional, Dict, List, Any
from string import ascii_uppercase

import dateparser as dateparser
import sqlalchemy.orm
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import create_engine

import logging

from src.ZMSession import ZMSession
from src.models import DBOptions, APIOptions
from src.dataclasses import ZMEvent

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
    def __init__(self, options: Optional[Dict] = None):
        """Python interface for ZoneMinder. Instantiate and query for information.

         If you do not pass any options, ZoneMinder's DB will be looked for locally. If you are on a remote host, you
         must pass options configured for an API connection or a remote DB connection.

        options:
          - host: ZoneMinder host (include schema [http(s)://])
          - port: ZoneMinder port for API or DB (Default 80 for API 3306 for DB)
          - user: ZoneMinder API/DB user (If using Authorization)
          - password: ZoneMinder API/DB password (If using Authorization)
          - database: ZoneMinder database name (Default "zm")
          - driver: ZoneMinder database driver (Default "mysql+mysqlconnector")
          - api_url: ZoneMinder API URL (Default "http://<host>:<port>/zm/api/")
          - portal_url: ZoneMinder Portal URL (Default "http://<host>:<port>/zm/")

        :param options: (dict) containing options to connect via API or DB.
        """
        if options is None:
            options = {}
        self.options: Optional[Dict] = options
        self.db_opts: Optional[Dict] = None
        self.api_opts: Optional[Dict] = None
        self.Events = []
        self.session: ZMSession
        logger.debug(f"ZoneMinder instantiated with options: {repr(options)}")
        if self.options:
            if self.options.get('api_url'):
                self.api_opts = APIOptions(**options)
                logger.debug(f"ZoneMinder Session being instantiated with API options: {self.api_opts}")
                self.session = ZMSession(self.api_opts, 'api')
            else:
                self.db_opts = DBOptions(**options)
                logger.debug(f"ZoneMinder Session being instantiated with DB options: {self.db_opts}")
                self.session = ZMSession(self.db_opts, 'db')
        else:
            self.db_opts = DBOptions(**options)
            logger.debug(f"ZoneMinder DEFAULT Session being instantiated with DB options: {self.db_opts}")
            self.session = ZMSession(self.db_opts, 'db')

    def get_events(self, options=None) -> List[ZMEvent]:
        """Will return a list of events based on filter criteria. Note that each time you call events,
        a new HTTP call/SQL Query is made.
            options (dict, optional): Various filters that will be applied to events. Defaults to {}.

                {
                    'event_id': string # specific event ID to fetch
                    'tz': string # long form timezone (example America/New_York),
                    'from': string # string # minimum start time (including human-readable
                                   # strings like '1 hour ago' or '10 minutes ago to 5 minutes ago' to create a range)
                    'to': string # string # maximum end time
                    'mid': int # monitor id
                    'min_alarmed_frames': int # minimum alarmed frames
                    'max_alarmed_frames': int # maximum alarmed frames
                    'object_only': boolean # if True will only pick events
                                           # that have detected objects

                }

        """
        if options is None:
            options = {}
        # Todo: make instantiating do the work
        mutate = Events(options=options, session=self.session).work()
        if mutate:
            for event in mutate:
                final = ZMEvent
                for attr in dir(event):
                    if attr.startswith('__') or attr[0] not in ascii_uppercase:
                        continue
                    setattr(final, attr, getattr(event, attr))
                self.Events.append(final)
        return self.Events


class Events:
    def __init__(self, options: Optional[Dict] = None, session: ZMSession = None, no_warn=False):
        """
        session (ZMSession) - API/SQL session used to query available events.
        no_warn (Boolean) - Turn the CLI warning off. Warning is logged regardless, this turns off the CLI warning.
        options:
          - event_id: string # specific event ID to fetch
          - tz: string # long form timezone (example America/New_York),
          - from: string # string # minimum start time (including human-readable
                             # strings like '1 hour ago' or '10 minutes ago to 5 minutes ago' to create a range)
          - to: string # string # maximum end time
          - mid: int # monitor id
          - min_alarmed_frames: int # minimum alarmed frames
          - max_alarmed_frames: int # maximum alarmed frames
          - object_only: boolean # if True will only pick events
                                 # that have detected objects

        """
        self.options: Optional[Dict] = options
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
        self.work()

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
        from sqlalchemy import text
        options = self.options
        if self.session and self.session.type == 'db':
            logger.debug(f"Retrieving events via SQL using options: {options}")
            eid: Optional[str] = options.get('event_id')
            tz: Optional[str] = options.get('tz')
            db_tz: dict = {}
            # query() is generative, can keep .where() and filter()'ing
            try:
                session: sqlalchemy.orm.Session
                session = self.session.db_sess()
                events = self.session.db.Events
                raw_data = session.query(events)

                if eid:
                    raw_data = raw_data.filter_by(Id=eid)
                if tz:
                    db_tz = {'TIMEZONE': tz}
                    logger.debug(f'Using TZ: {tz}')

                if options.get('from'):
                    from_list = options.get('from').split(" to ", 1)
                    if len(from_list) == 2:
                        from_start = dateparser.parse(from_list[0], settings=db_tz)
                        from_end = dateparser.parse(from_list[1], settings=db_tz)
                        if from_start > from_end:
                            from_start, from_end = from_end, from_start
                        q_text = f"StartDateTime>={from_start.strftime('%Y-%m-%d %H:%M:%S')}"
                        raw_data.filter(text(q_text))
                        q_text = f"StartDateTime<={from_end.strftime('%Y-%m-%d %H:%M:%S')}"
                        raw_data.filter(text(q_text))

                    else:
                        q_text = f"StartDateTime>=" \
                                 f"{dateparser.parse(from_list[0], settings=db_tz).strftime('%Y-%m-%d %H:%M:%S')}"
                        raw_data.filter(q_text)

                if options.get('to'):
                    to_list = options.get('to').split(" to ", 1)
                    if len(to_list) == 2:
                        to_start = dateparser.parse(to_list[0], settings=db_tz)
                        to_end = dateparser.parse(to_list[1], settings=db_tz)
                        if to_start > to_end:
                            to_start, to_end = to_end, to_start
                        q_text = f"EndTime<={to_end.strftime('%Y-%m-%d %H:%M:%S')}"
                        raw_data.filter(text(q_text))
                        q_text = f"EndTime>={to_start.strftime('%Y-%m-%d %H:%M:%S')}"
                    else:
                        q_text = f"EndTime<=" \
                                 f"{dateparser.parse(to_list[0], settings=db_tz).strftime('%Y-%m-%d %H:%M:%S')}"
                if options.get('mid'):
                    raw_data.where(MonitorId=options.get('mid'))
                if options.get('min_alarmed_frames'):
                    q_text = f"AlarmFrames>={options.get('min_alarmed_frames')}"
                    raw_data.filter(q_text)
                if options.get('max_alarmed_frames'):
                    q_text = f"AlarmFrames<={options.get('min_alarmed_frames')}"
                    raw_data.filter(q_text)
                if options.get('object_only'):
                    # MySQL/MariaDB regexp, PostgreSQL would be op('~')
                    raw_data.filter(events.Notes.op('regexp')(r'.*:detected:.*'))
                events = raw_data.all()
            except Exception as exc:
                logger.exception(f"Error querying DB for 'Events': {exc}", exc_info=True)
            else:
                return events
            finally:
                # Always close the session when not using a context manager
                session.close()

        # API
        elif self.session and self.session.type == 'api':
            if options is None:
                logger.error("No options provided, cannot retrieve events")
                return
            logger.info('Retrieving events via API')
            url_filter = ''
            tz = {}

            if options.get('event_id'):
                url_filter += '/Id=:' + str(options.get('event_id'))
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

                    url_filter += '/StartTime >=:' + from_start.strftime('%Y-%m-%d %H:%M:%S')
                    url_filter += '/StartTime <=:' + from_end.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    url_filter += '/StartTime >=:' + dateparser.parse(from_list[0], settings=tz).strftime(
                        '%Y-%m-%d %H:%M:%S')
            if options.get('to'):
                to_list = options.get('to').split(" to ", 1)
                if len(to_list) == 2:
                    to_start = dateparser.parse(to_list[0], settings=tz)
                    to_end = dateparser.parse(to_list[1], settings=tz)
                    if to_start > to_end:
                        to_start, to_end = to_end, to_start
                    url_filter += '/EndTime <=:' + to_end.strftime('%Y-%m-%d %H:%M:%S')
                    url_filter += '/EndTime >=:' + to_start.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    url_filter += '/EndTime <=:' + dateparser.parse(to_list[0], settings=tz).strftime(
                        '%Y-%m-%d %H:%M:%S')
            if options.get('mid'):
                url_filter += '/MonitorId =:' + str(options.get('mid'))
            if options.get('min_alarmed_frames'):
                url_filter += '/AlarmFrames >=:' + str(options.get('min_alarmed_frames'))
            if options.get('max_alarmed_frames'):
                url_filter += '/AlarmFrames <=:' + str(options.get('max_alarmed_frames'))
            if options.get('object_only'):
                url_filter += '/Notes REGEXP:detected:'  # 'detected' is the key for grabbing notes from DB and the zm_event_start/end wrappers

            # catch all
            if options.get('raw_filter'):
                url_filter += options.get('raw_filter')
            # print ('URL filter: ',url_filter)
            # todo - no need for url_prefix in options
            url_prefix = options.get('url_prefix', f'{self.api.api_url}/events/index')

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
            events = []
            while True:
                try:
                    r = self.api.make_request(url=url, query=params)
                except Exception as ex:
                    g.logger.error(f"Events: error making request for events -> {url}")
                    raise ex
                else:
                    events.extend(r.get('events'))
                    pagination = r.get('pagination')
                    self.pagination = pagination
                    if not pagination or not pagination.get('nextPage'):
                        break
                    curr_events += int(pagination.get('current'))
                    if curr_events >= num_events:
                        break
                    params['page'] += 1
            return events





        self.events: List = []
