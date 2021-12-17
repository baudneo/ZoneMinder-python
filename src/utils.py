from typing import Optional, Union


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
        return v