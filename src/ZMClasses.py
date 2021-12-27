import logging
import warnings
from typing import Optional, Union, Dict, Any, List

import dateparser
from sqlalchemy import asc, desc, and_
from sqlalchemy.orm import Session, Query

from src.ZMSession import ZMSession
from src.utils import str2bool
from src.dataclasses import ZMEvent, ZMState, ZMZone, ZMConfig, ZMStorage, ZMLogs, ZMUsers, DBOptions, APIOptions

logger = logging.getLogger('ZMClasses')
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_fmt = logging.Formatter(
    '%(asctime)s %(name)s[%(process)s]  %(levelname)s %(filename)s:%(lineno)d->[%(message)s]')
console_handler.setFormatter(console_fmt)
logger.addHandler(console_handler)


def Servers(
        session: ZMSession = None,
        session_options: Optional[Union[DBOptions, APIOptions]] = None,
):
    servers: list = []
    ret: Union[List, Query] = []
    if session and session.type == 'db':
        logger.info(f"Retrieving 'Servers' via SQL")
        db_sess: Optional[Session] = None
        with session.db_sess() as db_sess:
            servers_dataclass: ZMState = session.db.Servers
            ret = db_sess.query(servers_dataclass).all()

    elif session and session.type == 'api':
        logger.info(f"Retrieving 'Servers' via API")
        url = f"{session_options.api_url}/servers.json"
        r = session.api_sess.make_request(url=url)
        api_servers = r.get('servers')
        ret = []
        for server in api_servers:
            ret.append(server)
    return ret


def MontageLayouts(
        session: ZMSession = None,
        session_options: Optional[Union[DBOptions, APIOptions]] = None,
):
    montage_layouts: list = []
    ret: Union[List, Query] = []

    if session and session.type == 'db':
        logger.info(f"Retrieving 'MontageLayouts' via SQL")
        db_sess: Optional[Session] = None
        ret = None
        with session.db_sess() as db_sess:
            db_montage_layouts: ZMState = session.db.MontageLayouts
            ret = db_sess.query(db_montage_layouts).all()

    elif session and session.type == 'api':
        raise NotImplementedError("API not implemented for this function")
    return ret


def Groups(
        session: ZMSession = None,
        session_options: Optional[Union[DBOptions, APIOptions]] = None,
):
    groups: list = []
    ret: Union[List, Query] = []

    if session and session.type == 'db':
        logger.info(f"Retrieving 'Groups' via SQL")
        db_sess: Optional[Session] = None
        ret = None
        with session.db_sess() as db_sess:
            groups_dataclass: ZMState = session.db.Groups
            ret = db_sess.query(groups_dataclass).all()

    elif session and session.type == 'api':
        logger.info(f"Retrieving 'Groups' via API")
        url = f"{session_options.api_url}/groups.json"
        r = session.api_sess.make_request(url=url)
        api_groups = r.get('groups')
        ret = []
        for group in api_groups:
            ret.append(group)
    return ret

def Logs(
        session: ZMSession = None,
        options=None,
        session_options: Optional[Union[DBOptions, APIOptions]] = None,
):
    logs: list = []
    ret: Union[List, Query] = []
    if session and session.type == 'db':
        logger.info(f"Retrieving 'Logs' via SQL")
        db_sess: Optional[Session] = None
        ret = []
        with session.db_sess() as db_sess:
            db_logs: ZMLogs = session.db.Logs
            ret = db_sess.query(db_logs)
            if options.get('id'):
                ret = ret.filter(db_logs.Id == options.get('id'))
            if options.get('ascending'):
                ret = ret.order_by(asc(db_logs.TimeKey))
            if options.get('descending'):
                ret = ret.order_by(desc(db_logs.TimeKey))
            tz = options.get('tz')
            db_tz = {}
            if tz:
                db_tz = {'TIMEZONE': tz}
                logger.debug(f'Converting to TimeZone: {tz}')
            if options.get('from'):
                from_list = options.get('from').split(" to ", 1)
                if len(from_list) == 2:
                    from_start = dateparser.parse(from_list[0], settings=db_tz).timestamp()
                    from_end = dateparser.parse(from_list[1], settings=db_tz).timestamp()
                    if from_start > from_end:
                        from_start, from_end = from_end, from_start
                    logger.debug("'from' has 'to' in the 'from' option, querying with a range")
                    ret = ret.filter(and_(db_logs.TimeKey >= from_start,
                                          db_logs.TimeKey <= from_end))
                else:
                    ret = ret.filter(
                        db_logs.TimeKey >= dateparser.parse(from_list[0], settings=db_tz).timestamp())

            if options.get('to'):

                to_list = options.get('to').split(" to ", 1)
                if len(to_list) == 2:
                    to_start = dateparser.parse(to_list[0], settings=db_tz).timestamp()
                    to_end = dateparser.parse(to_list[1], settings=db_tz).timestamp()
                    if to_start > to_end:
                        to_start, to_end = to_end, to_start
                    ret = ret.filter(and_(db_logs.TimeKey >= to_start,
                                          db_logs.TimeKey <= to_end))
                else:
                    ret = ret.filter(
                        db_logs.TimeKey >= dateparser.parse(to_list[0], settings=db_tz).timestamp())
            ret = ret.all()

    elif session and session.type == 'api':
        logger.info(f"Retrieving 'Logs' via API")
        url_filter: str = ''
        params: dict = {}
        tz: dict = {}

        if options.get('id'):
            url_filter += f"/Id=:{options.get('event_id')}"
        if options.get('tz'):
            tz = {'TIMEZONE': options.get('tz')}
            logger.debug(f'Using TZ: {tz}')
        if options.get('ascending'):
            params['direction'] = 'asc'
        if options.get('from'):
            from_list = options.get('from').split(" to ", 1)
            if len(from_list) == 2:
                from_start = dateparser.parse(from_list[0], settings=tz)
                from_end = dateparser.parse(from_list[1], settings=tz)
                if from_start > from_end:
                    from_start, from_end = from_end, from_start

                url_filter += f"/TimeKey >=:{from_start.timestamp()}"
                url_filter += f"/TimeKey <=:{from_end.timestamp()}"
            else:
                url_filter += f"/TimeKey >=:{dateparser.parse(from_list[0], settings=tz).timestamp()}"
        if options.get('to'):
            to_list = options.get('to').split(" to ", 1)
            if len(to_list) == 2:
                to_start = dateparser.parse(to_list[0], settings=tz)
                to_end = dateparser.parse(to_list[1], settings=tz)
                if to_start > to_end:
                    to_start, to_end = to_end, to_start
                url_filter += f"/TimeKey <=:{to_end.timestamp()}"
                url_filter += f"/TimeKey >=:{to_start.timestamp()}"
            else:
                url_filter += f"/TimeKey <=:{dateparser.parse(to_list[0], settings=tz).timestamp()}"
        # catch all
        if options.get('raw_filter'):
            url_filter += options.get('raw_filter')
        # print ('URL filter: ',url_filter)
        url_prefix = f'{session_options.api_url}/logs/index'

        url = f'{url_prefix}{url_filter}.json'
        params = {
            'sort': 'TimeKey',
            'direction': 'desc',
        }
        # url = f"{session_options.api_url}/logs.json"
        r = session.api_sess.make_request(url=url)
        ret = r.get('logs')
    return ret


def TriggersX10(
        session: ZMSession = None,
        session_options: Optional[Union[DBOptions, APIOptions]] = None,
):
    triggers: list = []
    ret: Union[List, Query] = []
    if session and session.type == 'db':
        logger.info(f"Retrieving 'Triggers' via SQL")
        db_sess: Optional[Session] = None
        ret = None
        with session.db_sess() as db_sess:
            db_triggers: ZMState = session.db.TriggersX10
            ret = db_sess.query(db_triggers).all()

    elif session and session.type == 'api':
        logger.info(f"Retrieving 'Triggers' via API")
        url = f"{session_options.api_url}/triggers.json"
        r = session.api_sess.make_request(url=url)
        api_triggers = r.get('triggers')
        ret = []
        for trigger in api_triggers:
            ret.append(trigger)
    return ret


def Storage(
        session: ZMSession = None,
        options=None,
        session_options: Optional[Union[DBOptions, APIOptions]] = None,
):
    storage: list = []
    ret: Union[List, Query] = []
    if session and session.type == 'db':
        logger.info(f"Retrieving 'Storage' via SQL")
        db_sess: Optional[Session] = None
        with session.db_sess() as db_sess:
            db_storage: ZMStorage = session.db.Storage
            ret = db_sess.query(db_storage)
            from sqlalchemy import desc, asc
            if options.get('id'):
                ret = ret.filter(db_storage.Id == options.get('id'))
            if options.get('name'):
                ret = ret.filter(db_storage.Name == options.get('name'))
            if options.get('path'):
                ret = ret.filter(db_storage.Path == options.get('path'))
            if options.get('server_id'):
                ret = ret.filter(db_storage.ServerId == options.get('server_id'))
            if options.get('used_disk_space', {}).get('descending'):
                ret = ret.order_by(desc(db_storage.DiskSpace))
            if options.get('used_disk_space', {}).get('ascending'):
                ret = ret.order_by(asc(db_storage.DiskSpace))
            if options.get('enabled'):
                ret = ret.filter(db_storage.Enabled == 1)
            ret = ret.all()

    elif session and session.type == 'api':
        logger.info(f"Retrieving 'Storage' via API")
        url = f"{session_options.api_url}/storage.json"
        r = session.api_sess.make_request(url=url)
        ret = r.get('storage')
        if options.get('id'):
            ret = [x for x in ret if x.get('Storage').get('Id') == str(options.get('id'))]
        if options.get('name'):
            ret = [x for x in ret if x.get('Storage').get('Name') == options.get('name')]
        if options.get('path'):
            ret = [x for x in ret if x.get('Storage').get('Path') == options.get('path')]
        if options.get('server_id'):
            ret = [x for x in ret if x.get('Storage').get('ServerId') == str(options.get('server_id'))]
        if options.get('used_disk_space', {}).get('descending'):
            ret = sorted(ret, key=lambda x: x.get('Storage').get('DiskSpace'), reverse=True)
        if options.get('used_disk_space', {}).get('ascending'):
            ret = sorted(ret, key=lambda x: x.get('Storage').get('DiskSpace'))
        if options.get('enabled'):
            ret = [x for x in ret if x.get('Storage').get('Enabled') is True]

    return ret


def Configs(
        session: ZMSession = None,
        options=None,
        session_options: Optional[Union[DBOptions, APIOptions]] = None,
):
    configs: list = []
    ret: Union[List, Query] = []
    if session and session.type == 'db':
        logger.info(f"Retrieving 'Configs' via SQL")
        db_sess: Optional[Session] = None
        with session.db_sess() as db_sess:
            configs_dataclass: ZMConfig = session.db.Config
            ret = db_sess.query(configs_dataclass)
            if options.get('id'):
                ret = ret.filter(configs_dataclass.Id == options.get('id'))
            if options.get('name'):
                ret = ret.filter(configs_dataclass.Name == options.get('name'))
            if options.get('category'):
                ret = ret.filter(configs_dataclass.Category == options.get('category'))
            if options.get('type'):
                ret = ret.filter(configs_dataclass.Type == options.get('type'))
            ret = ret.all()
    elif session and session.type == 'api':
        logger.info(f"Retrieving 'Configs' via API")
        url = f"{session_options.api_url}/configs.json"
        r = session.api_sess.make_request(url=url)
        api_configs = r.get('configs')
        ret = []
        for config in api_configs:
            ret.append(config)
    return ret


def Monitors(
        session: ZMSession = None,
        session_options: Optional[Union[DBOptions, APIOptions]] = None,
):
    monitors: list = []
    ret: Union[List, Query] = []
    if session and session.type == 'db':
        logger.info(f"Retrieving 'Monitors' via SQL")
        db_sess: Optional[Session] = None
        with session.db_sess() as db_sess:
            mons: ZMEvent = session.db.Monitors
            ret = db_sess.query(mons).all()

    elif session and session.type == 'api':
        logger.info(f"Retrieving 'Monitors' via API")
        url = f"{session_options.api_url}/monitors.json"
        r = session.api_sess.make_request(url=url)
        # mons = r.get('monitors')
        ret = r.get('monitors')
        # for mon in mons:
        #     ret.append(mon)
    return ret


def Zones(
        session: ZMSession = None,
        options: dict = None,
        session_options: Optional[Union[DBOptions, APIOptions]] = None,
):
    if options is None:
        options = {}
    zones: list = []
    ret: Union[List, Query] = []
    if session and session.type == 'db':
        logger.info(f"Retrieving 'Zones' via SQL")
        db_sess: Optional[Session] = None
        with session.db_sess() as db_sess:
            db_zones: ZMZone = session.db.Zones
            ret = db_sess.query(db_zones)
            if options.get('id'):
                ret = ret.filter(db_zones.Id == options.get('id'))
            if options.get('monitor_id'):
                ret = ret.filter(db_zones.MonitorId == options.get('monitor_id'))
            if options.get('name'):
                ret = ret.filter(db_zones.Name == options.get('name'))
            if options.get('type'):
                ret = ret.filter(db_zones.Type == options.get('type'))

    elif session and session.type == 'api':
        logger.info(f"Retrieving 'Zones' via API")
        url = f"{session_options.api_url}/zones/index.json"
        r = session.api_sess.make_request(url=url)
        ret = r.get('zones')
        if options.get('id'):
            ret = [x for x in ret if x.get('Zone').get('Id') == str(options.get('id'))]
        if options.get('monitor_id'):
            ret = [x for x in ret if x.get('Zone').get('MonitorId') == str(options.get('monitor_id'))]
        if options.get('name'):
            ret = [x for x in ret if x.get('Zone').get('Name') == str(options.get('name'))]
        if options.get('type'):
            ret = [x for x in ret if x.get('Zone').get('Type') == str(options.get('type'))]

    return ret


def States(
        options: Optional[Dict] = None,
        session: ZMSession = None,
        session_options: Optional[Union[DBOptions, APIOptions]] = None,
):
    states: list = []
    ret: Union[List, Query] = []
    if session and session.type == 'db':
        logger.info(f"Retrieving 'States' via SQL")
        db_sess: Optional[Session] = None
        with session.db_sess() as db_sess:
            db_states: ZMState = session.db.States
            ret = db_sess.query(db_states)
            if options.get('id'):
                ret = ret.filter(db_states.Id == options.get('id'))
            if options.get('name'):
                ret = ret.filter(db_states.Name == options.get('name'))
            if options.get('current'):
                ret = ret.filter(db_states.IsActive == 1)

    elif session and session.type == 'api':
        logger.info(f"Retrieving 'States' via API")
        url = f"{session_options.api_url}/states.json"
        r = session.api_sess.make_request(url=url)
        ret = r.get('states')
        if options.get('id'):
            ret = [x for x in ret if x.get('State').get('Id') == str(options.get('id'))]
        if options.get('name'):
            ret = [x for x in ret if x.get('State').get('Name') == str(options.get('name'))]
        if options.get('current'):
            ret = [x for x in ret if x.get('State').get('IsActive') == '1']
    return ret


def Users(
        options: Optional[Dict] = None,
        session: ZMSession = None,
        session_options: Optional[Union[DBOptions, APIOptions]] = None,

):
    users: list = []
    ret: Union[List, Query] = []
    if session and session.type == 'db':
        logger.info(f"Retrieving 'Users' via SQL")
        db_sess: Optional[Session] = None
        with session.db_sess() as db_sess:
            db_users: ZMUsers = session.db.Users
            ret = db_sess.query(db_users)
            if options.get('id'):
                ret = ret.filter(db_users.Id == options.get('id'))
            if options.get('name') or options.get('username'):
                val_ = options.get('name', options.get('username'))
                ret = ret.filter(db_users.Username == val_)
            if options.get('api_active') is True or options.get('apienabled') is True:
                ret = ret.filter(db_users.ApiEnabled == 1)
            if options.get('is_active') is True or options.get('enabled') is True:
                ret = ret.filter(db_users.Enabled == 1)
            ret = ret.all()

    elif session and session.type == 'api':
        logger.info(f"Retrieving 'Users' via API")
        params: dict = {}
        url = f'{session_options.api_url}/users/index.json'

        r = session.api_sess.make_request(url=url, query=params)
        ret = r.get('users')
        if options.get('id'):
            ret = [x for x in ret if x.get('User').get('Id') == options.get('id')]
        if options.get('name') or options.get('username'):
            val_ = options.get('name', options.get('username'))
            if ret is not None:
                ret = [x for x in ret if x.get('User').get('Username') == val_]
        if options.get('api_active') is True or options.get('apienabled') is True:
            if ret is not None:
                ret = [x for x in ret if x.get('User').get('ApiEnabled') == '1']
        if options.get('is_active') is True or options.get('enabled') is True:
            ret = [x for x in ret if x.get('User').get('Enabled') == '1']

    return ret


def Events(
        options: Optional[Dict] = None,
        session: ZMSession = None,
        session_options: Optional[Union[DBOptions, APIOptions]] = None,
        no_warn: bool = False,
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
    if options.get('object_only') is not None:
        options['object_only'] = str2bool(options['object_only'])

    if not options:
        msg = f"No filters passed to <Events> via the 'options' parameter, grabbing ALL events... If this is " \
              f"unintended, use a filter via 'options'."
        if not no_warn:
            msg = f"{msg} To turn this warning off pass 'True' to the no_warn parameter."
            warnings.warn(msg)
        # Log the warning regardless
        logger.warning(msg=msg)

    events: list = []
    raw_data: Any
    # Database
    if session and session.type == 'db':
        from sqlalchemy.sql.expression import and_
        logger.debug(f"Retrieving events via SQL using options: {options}")
        eid: Optional[str] = options.get('event_id')
        tz: Optional[Union[str, dict]] = options.get('tz')
        db_tz: dict = {}
        raw_data: Query
        # query() is generative, can keep .where() and filter()'ing
        db_sess: Optional[Session] = None
        try:
            db_sess = session.db_sess()
            db_events: Union[ZMEvent, List[Dict[str: str]]] = session.db.Events
            # events = session.auto_map.classes.Events
            raw_data = db_sess.query(db_events)

            if eid:
                logger.debug(f"Using EventId to filter SQL")
                raw_data = raw_data.filter(events.Id == int(eid))
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
                    raw_data = raw_data.filter(and_(db_events.StartDateTime >= from_start,
                                                    db_events.StartDateTime <= from_end))
                else:
                    raw_data = raw_data.filter(
                        db_events.StartDateTime >= dateparser.parse(from_list[0], settings=db_tz))

            if options.get('to'):
                logger.debug(f"Using EndDateTime to filter SQL")
                to_list = options.get('to').split(" to ", 1)
                if len(to_list) == 2:
                    to_start = dateparser.parse(to_list[0], settings=db_tz)
                    to_end = dateparser.parse(to_list[1], settings=db_tz)
                    if to_start > to_end:
                        to_start, to_end = to_end, to_start
                    raw_data = raw_data.filter(and_(db_events.EndDateTime >= to_start,
                                                    db_events.EndDateTime <= to_end))
                else:
                    raw_data = raw_data.filter(
                        db_events.EndDateTime >= dateparser.parse(to_list[0], settings=db_tz))

            if options.get('mid'):
                logger.debug(f'Using MonitorId to filter SQL')
                raw_data = raw_data.filter(db_events.MonitorId == options.get('mid'))
            if options.get('min_alarmed_frames'):
                logger.debug(f"Using minimum AlarmFrames to filter SQL")
                raw_data = raw_data.filter(db_events.AlarmFrames >= options.get('min_alarmed_frames'))
            if options.get('max_alarmed_frames'):
                logger.debug(f"Using maximum AlarmFrames to filter SQL")
                raw_data = raw_data.filter(db_events.AlarmFrames <= options.get('max_alarmed_frames'))
            if options.get('object_only'):
                logger.debug(f"Using detected objects to filter SQL")
                # MySQL/MariaDB regexp, Postgres would be op('~')
                raw_data = raw_data.filter(db_events.Notes.op('regexp')(r'.*:detected:.*'))
            events = raw_data.all()  # return a list of matches
        except Exception as exc:
            logger.exception(f"Error querying DB for 'Events': {exc}", exc_info=True)
        else:
            return events
        finally:
            # Always close the session when not using a context manager
            if db_sess:
                logger.debug(f"Closing DB session after querying for events")
                db_sess.close()

    # API
    elif session and session.type == 'api':
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
        url_prefix = f'{session_options.api_url}/events/index'

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
        events = []
        while True:
            try:
                # r = session.api_sess.get(url=url, params=params)
                r = session.api_sess.make_request(url=url, query=params)
            except Exception as ex:
                logger.error(f"Events: error making request for events -> {url}")
                raise ex
            else:
                events.extend(r.get('events'))
                pagination = r.get('pagination')
                if not pagination or not pagination.get('nextPage'):
                    break
                curr_events += int(pagination.get('current'))
                if curr_events >= num_events:
                    logger.debug(f"get_events:API: Hit 'Events' limit/max_events ({num_events})")
                    break
                params['page'] += 1
        return events
