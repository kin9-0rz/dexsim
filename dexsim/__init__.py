import os

DEBUG_MODE = False

MAIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

with open(os.path.join(MAIN_PATH, 'datas', 'filters.txt')) as f:
    FILTERS = f.read().splitlines()
