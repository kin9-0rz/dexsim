import logging
import os

DEBUG = False

MAIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


with open(os.path.join(MAIN_PATH, 'datas', 'filters.txt')) as f:
    FILTERS = f.read().splitlines()

log_path = os.path.join(MAIN_PATH, 'dexsim.log')

logging.basicConfig(
    level=logging.DEBUG,
    filename=log_path,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    filemode='w')
