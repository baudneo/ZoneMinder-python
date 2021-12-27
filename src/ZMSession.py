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

from sqlalchemy import create_engine, Table, MetaData
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.automap import automap_base

from requests import Session
from requests.packages.urllib3 import disable_warnings
from requests.exceptions import HTTPError
from urllib3.exceptions import InsecureRequestWarning

from src.dataclasses import ZMDB
from src.models import DBOptions, APIOptions

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


def MetaDataCache(metadata: Optional[MetaData] = None, file=None):
    """Will cache MetaData to disk. Pass it an instantiated MetaData class THAT HAS NOT BEEN REFLECTED and has an engine bound to it.

    :param file: (str) - PathName of cache file. [Default: /tmp/ZM_DBMetaData.pkl]
    """
    default_filename = f'/tmp/ZM_DBMetaData.pkl'
    if file:
        try:
            file = Path(file)
        except Exception as exc:
            logger.warning(f"The 'file' ({file}) passed to MetaDataCache is invalid, using default")
            file = Path(default_filename)
    else:
        file = Path(default_filename)
    from pickle import dump, load
    if file.is_file():
        try:
            with file.open('rb') as f:
                metadata = load(f)
        except Exception as exc:
            logger.error(f"Exception while loading pickled metadata from disk: {exc}")
            logger.debug(f"Populating new metadata")
            metadata.reflect()
        else:
            logger.debug(f'Loaded metadata from disk cache at {file}')
    else:
        if metadata:
            metadata.reflect()
            try:
                file.touch(exist_ok=True)
                with file.open('wb') as f:
                    dump(metadata, f)
            except Exception as exc:
                logger.error(f"Exception while pickling metadata to disk: {exc}")
            else:
                logger.debug(f"Cached metadata to disk")
    return metadata


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
        self.options: Union[DBOptions, APIOptions] = options
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
                logger.warning(f"Use the option 'conf_path' or set the environment variable PYZM_CONF_PATH to specify "
                               f"the path to the ZM configuration files")
                raise FileNotFoundError(f"The ZM configuration path 'conf_path' ({db_config['conf_path']})"
                                        f" does not exist!")
            if conf_data:
                if not db_config.get('dbuser'):
                    db_config['dbuser'] = conf_data.get('ZM_DB_USER')
                if not db_config.get('dbpassword'):
                    db_config['dbpassword'] = conf_data.get('ZM_DB_PASS')
                if not db_config.get('dbhost'):
                    db_config['dbhost'] = conf_data.get('ZM_DB_HOST')
                if not db_config.get('dbname'):
                    db_config['dbname'] = conf_data.get('ZM_DB_NAME')
            logger.debug(f"After loading {len(files)} ({files}) ZM config files, db_config is: {db_config}")
            if (
                    not db_config['dbhost']
                    or not db_config['dbuser']
                    or not db_config['dbpassword']
                    or not db_config['dbname']
                    or not db_config['driver']
            ):
                logger.fatal(f"There is not enough information to query the database!")
                return

            conn_str = f"{db_config['driver']}://{db_config['dbuser']}:{db_config['dbpassword']}@" \
                       f"{db_config['dbhost']}/{db_config['dbname']}"
            show_conn_str = conn_str.replace(db_config['dbpassword'],
                                             '<sanitized>').replace(db_config['dbhost'], '<sanitized>')
            try:
                logger.debug(f"Connecting to ZM DB: {show_conn_str if options.sanitize else conn_str}")
                engine = create_engine(conn_str, pool_recycle=3600)
            except SQLAlchemyError as e:
                engine = None
                logger.exception(f"Failed to connect to ZM DB", exc_info=True)
            else:
                logger.info(f"Connected to DB")
                self.db_sess = sessionmaker(bind=engine)
                # Prepare metadata ourselves, pickle it to a file for caching as the schema SHOULD not change
                self.metadata = MetaDataCache(metadata=MetaData(engine))
                # automap, populate python classes using Table schema.
                # classes are mapped to a dataclass ive prepared based on ZM table schemas as well
                self.auto_map: automap_base = Base(metadata=self.metadata)
                self.auto_map.prepare(engine)
                self.db: ZMDB = ZMDB()
                for attr in dir(self.auto_map.classes):
                    if attr.startswith('_') or not attr[0].isupper():
                        continue
                    setattr(self.db, attr, (value := getattr(self.auto_map.classes, attr)))



        elif self.type == 'api':
            from src.ZMAPI import ZMApi
            self.user = options.user
            self.port = options.port or 80
            self.password = options.password
            self.host = options.host
            self.api_sess = ZMApi(options)

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
