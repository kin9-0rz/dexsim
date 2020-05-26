import json
import logging
import os
import tempfile

from pyadb3 import ADB
from zeroclient import zero_client as zc

from dexsim import logs

logger = logging.getLogger(__name__)

class Driver:

    def __init__(self):
        self.client = zc.SnippetClient()
        self.client.connect()
        print(self.client.rpc('hello'))

    def rpc_static_method(self, data):
        return self.client.rpc('InvokeStaticMethod', data)
