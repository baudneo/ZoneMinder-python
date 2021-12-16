__VERSION__ = '0.0.1'

import logging
DEBUG_LEVELV_NUM = 9
logging.addLevelName(DEBUG_LEVELV_NUM, "DEBUGV")
def debugv(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    self._log(DEBUG_LEVELV_NUM, message, args, **kws)
logging.Logger.debugv = debugv