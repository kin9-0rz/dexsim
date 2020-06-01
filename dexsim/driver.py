import json
import logging
import os
import tempfile

from pyadb3 import ADB
from zeroclient import zero_client as zc


PLUGIN_PATH = '/data/local/tmp/plugins/'

class Driver:

    def __init__(self):
        self.adb = ADB()
        
    #  TODO 需要重新考虑这个过程
    # APK是否会挂？
    # 服务是否会挂？

    def push_apk_to_device(self, apk_path):
        self.adb.run_shell_cmd(['mkdir', PLUGIN_PATH])
        self.adb.run_cmd(['push', apk_path, PLUGIN_PATH])
        self.adb.run_shell_cmd(
            ['am', 'start', '-n', 'mikusjelly.zerolib/mikusjelly.zero.MainActivity'])
        self.adb.run_cmd(['forward', 'tcp:8888', 'tcp:9999'])
        self.init_client()
    
    def init_client(self):
        self.client = zc.SnippetClient()
        while True:
            try:
                self.client.connect()
                break
            except Exception as e:
                logging.warn(str(e) + '准备重连...')
                continue

    def rm_device_file(self):
        # 停止进程
        self.adb.run_shell_cmd(['am', 'force-stop', 'mikusjelly.zerolib'])  # 停止进程
        self.adb.run_cmd(['forward', '--remove-all'])
        self.adb.run_shell_cmd(['rm', '-rf', PLUGIN_PATH])

    def test_connect(self):
        try:
            logging.info(self.client.rpc('hello'))
        except Exception as e:
            logging.warn(str(e) + '准备重连...')
            self.adb.run_shell_cmd(['am', 'force-stop', 'mikusjelly.zerolib'])
            self.adb.run_cmd(['forward', '--remove-all'])
            self.adb.run_cmd(['forward', 'tcp:8888', 'tcp:9999'])
            self.adb.run_shell_cmd(
            ['am', 'start', '-n', 'mikusjelly.zerolib/mikusjelly.zero.MainActivity'])
            self.init_client()

    def rpc_static_method(self, data):
        self.test_connect()
        try:
            result = self.client.rpc('InvokeStaticMethod', data)

            if result['error']:
                logging.warn(data)
                logging.warn(result['error'])
            return result['result']
        except Exception as e:
            print(e)
            return None

    def rpc_static_field(self, data):
        try:
            result = self.client.rpc('GetFieldValue', data)

            if result['error']:
                logging.warn(data)
                logging.warn(result['error'])
            return result['result']
        except Exception as e:
            print(e)
            return None