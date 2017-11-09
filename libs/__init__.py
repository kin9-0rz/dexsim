"""
存放log配置
"""
import logging
import os

log_path = os.path.join(os.path.dirname(__file__), '..', 'dexsim.log')

logging.basicConfig(
    level=logging.DEBUG,
    filename=log_path,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    filemode='w'
)
