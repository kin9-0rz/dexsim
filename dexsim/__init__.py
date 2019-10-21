import os

_global_dict = None

DEBUG_MODE = False
def _init():
    global _global_dict
    _global_dict = {}


def set_value(name, value):
    _global_dict[name] = value


def get_value(name):
    return _global_dict.get(name, None)


_init()
set_value('DEBUG_MODE', False)
set_value('PLUGIN_NAME', None)


MAIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

with open(os.path.join(MAIN_PATH, 'datas', 'filters.txt')) as f:
    FILTERS = f.read().splitlines()
