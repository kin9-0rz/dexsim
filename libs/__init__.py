"""
存放log配置
"""
import logging
import os

log_path = os.path.join(os.path.dirname(__file__), '..', 'dexsim.log')

logging.basicConfig(filename=log_path,
                    format='%(asctime)s %(name)s %(levelname)s: %(message)s',
                    filemode='w', level=logging.DEBUG)
