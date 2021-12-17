import logging
import warnings
from typing import Optional, Union, Dict, Any, List

import dateparser
from sqlalchemy.orm import Session, Query

from src.ZMSession import ZMSession
from src.utils import str2bool
from src.dataclasses import ZMEvent
from src.models import DBOptions, APIOptions

logger = logging.getLogger('ZMClasses')
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_fmt = logging.Formatter(
    '%(asctime)s %(name)s[%(process)s]  %(levelname)s %(filename)s:%(lineno)d->[%(message)s]')
console_handler.setFormatter(console_fmt)
logger.addHandler(console_handler)



def Monitors(
            session: ZMSession = None,
            session_options: Optional[Union[DBOptions, APIOptions]] = None,
):
    monitors: list = []
    if session and session.type == 'db':
        logger.info(f"Retrieving 'Monitors' via SQL")
        db_sess: Optional[Session] = None
        ret = None
        with session.db_sess() as db_sess:
            mons: ZMEvent = session.db.Monitors
            ret = db_sess.query(mons).all()
        return ret

    elif session and session.type == 'api':
        logger.info(f"Retrieving 'Monitors' via API")
        url = f"{session_options.api_url}/monitors.json"
        r = session.api_sess.make_request(url=url)
        mons = r.get('monitors')
        ret = []
        for mon in mons:
            ret.append(mon)
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
                    raw_data = raw_data.filter(and_(db_events.StartDateTime >= from_start,
                                                    db_events.StartDateTime <= from_end))
                else:
                    raw_data = raw_data.filter(db_events.StartDateTime >= dateparser.parse(from_list[0], settings=db_tz))

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
                logger.debug(f"DB Session closed!")

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
        # todo - no need for url_prefix in options
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