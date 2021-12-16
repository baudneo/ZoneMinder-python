from configparser import ConfigParser
from os import getenv
from glob import glob as g_glob
from pathlib import Path
from typing import Union, Optional

import logging
from logging import handlers

from dataclasses import dataclass, field

from dotenv import load_dotenv

from pydantic import BaseModel

from sqlalchemy import create_engine, Table
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from requests import Session
from requests.packages.urllib3 import disable_warnings
from requests.exceptions import HTTPError
from urllib3.exceptions import InsecureRequestWarning

from src.dataclasses import ZMDB

from sqlalchemy.ext.automap import automap_base
Base: automap_base = automap_base()


logger = logging.getLogger('ZMSess')
logger.setLevel(logging.DEBUG)
# file_handler = logging.FileHandler('zmsession.log')
# syslog_handler = handlers.SysLogHandler(address='/dev/log')
console_handler = logging.StreamHandler()
main_fmt = logging.Formatter(
    '%(asctime)s %(name)s[%(process)s]  %(levelname)s %(filename)s:%(lineno)d->[%(message)s]'
)
console_handler.setFormatter(main_fmt)
syslog_fmt = logging.Formatter(
    '%(levelname)s [%(processname)s] [%(message)s]'
)
logger.addHandler(console_handler)


class MetaDataCache:
    def __init__(self, metadata=None, file=None):
        default_filename = f'/tmp/ZMMetaData.pkl'
        if file:
            try:
                self.file = Path(file)
            except Exception as exc:
                logger.warning(f"The 'file' ({file}) passed to MetaDataCache is invalid, using default")
        else:
            Path(default_filename)
        self.metadata = metadata

    def proc(self):
        from pickle import dump, load
        if self.metadata:
            self.file.touch(exist_ok=True)
            try:
                with self.file.open('wb') as f:
                    dump(self.metadata, f)
            except Exception as exc:
                logger.exception(f"Exception Message while pickling metadata to disk: {exc}", exc_info=True)
            else:
                logger.debug(f"Cached metadata to disk")
                return None
        else:
            if self.file.is_file():
                try:
                    with self.file.open('rb') as f:
                        self.metadata = load(f)
                except Exception as exc:
                    logger.exception(f"Exception while loading pickled metadata from disk: {exc}", exc_info=True)
                else:
                    logger.debug(f'Loaded metadata from disk cache at {self.file}')
                    return self.metadata
            else:
                logger.info(f"No metadata cached to disk at {self.file}")



from src.models import DBOptions, APIOptions

class ZMSession:
    """Creates a session to query ZM using SQL or API calls, ambiguous to the user. High level getters will obfuscate
    the lower level dealings
    """

    handler: Union[Session, sessionmaker]
    type: str
    user: str
    password: str
    host: str
    port: int
    db_name: str
    db_driver: str

    def __init__(self, options: Union[DBOptions, APIOptions], _type: str = None):
        # Assume 'db' if no type is provided
        if not _type:
            _type = 'db'
        load_dotenv()
        self.type = _type
        if self.type == 'db':
            # Credit to @pliablepixels for this code, no need for me to reinvent the wheel.
            db_config = {
                'conf_path': getenv('PYZM_CONFPATH', '/etc/zm'),  # we need this to get started
                'dbuser': getenv('PYZM_DBUSER'),
                'dbpassword': getenv('PYZM_DBPASSWORD'),
                'dbhost': getenv('PYZM_DBHOST'),
                'dbname': getenv('PYZM_DBNAME'),
                'driver': getenv('PYZM_DBDRIVER', 'mysql+mysqlconnector')
            }
            logger.debug(f"After loading environment variables, db_config is: {db_config}")
            if options.conf_path:
                db_config['conf_path'] = options.conf_path
            if options.user:
                db_config['dbuser'] = options.user
            if options.password:
                db_config['dbpassword'] = options.password
            if options.host:
                db_config['dbhost'] = options.host
            if options.db_name:
                db_config['dbname'] = options.db_name
            if options.db_driver:
                db_config['driver'] = options.db_driver
            logger.debug(f"After PARSING options, db_config is: {db_config}")
            # read all config files in order
            files = []
            conf_data = None
            if Path(f'{db_config["conf_path"]}/conf.d').exists():
                logger.debug(f"Found ZM {db_config['conf_path']}/conf.d directory")
                for f in g_glob(f'{db_config["conf_path"]}/conf.d/*.conf'):
                    files.append(f)
                files.sort()
                if Path(f"{db_config['conf_path']}/zm.conf").exists():
                    logger.debug(f"Found {db_config['conf_path']}/zm.conf")
                    files.insert(0, f"{db_config['conf_path']}/zm.conf")
                conf_data = self.read_zm_confs(files)
            else:
                logger.warning(f"The ZM configuration file path 'conf_path' does not exist!")

            if conf_data:
                if not db_config.get('dbuser'):
                    db_config['dbuser'] = conf_data.get('ZM_DB_USER')
                if not db_config.get('dbpassword'):
                    db_config['dbpassword'] = conf_data.get('ZM_DB_PASS')
                if not db_config.get('dbhost'):
                    db_config['dbhost'] = conf_data.get('ZM_DB_HOST')
                if not db_config.get('dbname'):
                    db_config['dbname'] = conf_data.get('ZM_DB_NAME')
            logger.debug(f"After loading {len(files)} ZM config files, db_config is: {db_config}")
            if not db_config['dbhost'] or not db_config['dbuser'] or not db_config['dbpassword'] or not db_config['dbname']:
                logger.fatal(f"There is not enough information to query the database!")
                return

            cstr = f"{db_config['driver']}://{db_config['dbuser']}:{db_config['dbpassword']}@" \
                   f"{db_config['dbhost']}/{db_config['dbname']}"
            try:
                logger.debug(f"Connecting to ZM DB: {cstr}")
                engine = create_engine(cstr, pool_recycle=3600)
            except SQLAlchemyError as e:
                engine = None
                logger.exception(f"Failed to connect to ZM DB", exc_info=True)
            else:
                logger.info(f"Connected to DB")
                self.db_sess = sessionmaker(bind=engine)
                from sqlalchemy import MetaData
                # Todo: cache the metadata as the scheme will not change
                # Prepare metadata ourselves, pickle it to a file for caching as the schema SHOULD not change
                self.metadata = MetaData(engine)
                # reflect all tables only once in production and cache metadata to disk
                self.metadata.reflect()
                # automap, populate python classes using schema data. Classes are pre declared to override their
                # __repr__ methods
                self.auto_map: automap_base = Base(metadata=self.metadata)
                self.auto_map.prepare(engine)

                self.db = ZMDB()
                from string import ascii_uppercase
                for attr in dir(self.auto_map.classes):
                    if attr.startswith('__') or attr[0] not in ascii_uppercase:
                        continue
                    setattr(self.db, attr, getattr(self.auto_map.classes, attr))

                # self.db.Events = self.auto_map.classes.Events
                # self.db.Monitors = self.auto_map.classes.Monitors
                # self.db.Config = self.auto_map.classes.Config
                # self.db.ControlPresets = self.auto_map.classes.ControlPresets
                # self.db.Controls = self.auto_map.classes.Controls
                # self.db.Devices = self.auto_map.classes.Devices
                # self.db.Event_Summaries = self.auto_map.classes.Event_Summaries
                # self.db.Events_Archived = self.auto_map.classes.Events_Archived
                # self.db.Events_Day = self.auto_map.classes.Events_Day
                # self.db.Events_Hour = self.auto_map.classes.Events_Hour
                # self.db.Events_Week = self.auto_map.classes.Events_Week
                # self.db.Events_Month = self.auto_map.classes.Events_Month
                # self.db.Filters = self.auto_map.classes.Filters
                # self.db.Frames = self.auto_map.classes.Frames
                # self.db.Groups = self.auto_map.classes.Groups
                # self.db.Groups_Monitors = self.auto_map.classes.Groups_Monitors
                # self.db.Logs = self.auto_map.classes.Logs
                # self.db.Manufacturers = self.auto_map.classes.Manufacturers
                # self.db.Maps = self.auto_map.classes.Maps
                # self.db.Models = self.auto_map.classes.Models
                # self.db.MonitorPresets = self.auto_map.classes.MonitorPresets
                # self.db.Monitor_Status = self.auto_map.classes.Monitor_Status
                # self.db.MontageLayouts = self.auto_map.classes.MontageLayouts
                # self.db.Servers = self.auto_map.classes.Servers
                # self.db.Sessions = self.auto_map.classes.Sessions
                # self.db.Snapshot_Events = self.auto_map.classes.Snapshot_Events
                # self.db.Snapshots = self.auto_map.classes.Snapshots
                # self.db.States = self.auto_map.classes.States
                # self.db.Stats = self.auto_map.classes.Stats
                # self.db.Storage = self.auto_map.classes.Storage
                # self.db.TriggersX10 = self.auto_map.classes.TriggersX10
                # self.db.Users = self.auto_map.classes.Users
                # self.db.ZonePresets = self.auto_map.classes.ZonePresets
                # self.db.Zones = self.auto_map.classes.Zones

        elif self.type == 'api':
            self.user = options.get('user')
            self.port = options.get('port', 80)
            self.password = options.get('password')
            self.host = options.get('host')
            self.api_sess = Session()

    def get(self, params: dict, **kwargs) -> dict:
        """Request information from ZM, this will use either API or SQL calls depending on the type of session

        params: dict - {
                'type': event, monitor, config, zone, state.
                'id': Event ID or Monitor ID.
                'name': Monitor, Zone or State name.
                'start_time': If requesting events, the time of the event
                'end_time':

        }

        """

    def read_zm_confs(self, files: list):
        config_file = ConfigParser(interpolation=None, inline_comment_prefixes='#')
        f = None
        try:
            for f in files:
                with open(f, 'r') as s:
                    # This adds [zm_root] section to the head of each zm .conf.d config file,
                    # not physically only in memory
                    config_file.read_string(f'[zm_root]\n{s.read()}')
        except Exception as exc:
            logger.error(f"Error opening {f if f else files} -> {exc}")
            return None
        else:
            return config_file['zm_root']

