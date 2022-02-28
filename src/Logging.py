import logging

from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger("ZM")


class ZMDBLogHandler(logging.Handler):
    levels_no = {
        "debug": 1,
        "info": 0,
        "warning": -1,
        "error": -2,
        "critical": -3,
        "off": -5,
    }
    levels_name = {
        "debug": "DBG",
        "info": "INF",
        "warning": "WAR",
        "error": "ERR",
        "panic": "PNC",  # Not real just there for now
        "critical": "FAT",
        "off": "OFF",
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
            cmd = self.table.insert().values(
                TimeKey=time(),
                Component=component,
                ServerId=server_id,
                Pid=pid,
                Level=_level,
                Code=lvl,
                Message=message,
                File=record.filename,
                Line=record.lineno,
            )
            self.conn.execute(cmd)
        except SQLAlchemyError as e:
            logger.error(f"Error writing to database: {e}")

