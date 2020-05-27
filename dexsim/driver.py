import json
import logging
import os
import tempfile

from pyadb3 import ADB
from zeroclient import zero_client as zc


class Driver:

    def __init__(self):
        self.client = zc.SnippetClient()
        while True:
            try:
                self.client.connect()
                break
            except Exception:
                continue
        logging.info(self.client.rpc('hello'))

    def rpc_static_method(self, data):
        try:
            result = self.client.rpc('InvokeStaticMethod', data)

            if result['error']:
                logging.warn(data)
                logging.warn(result['error'])
            return result['result']
        except Exception as e:
            print(e)
            return None
