import json
import logging
import os
import tempfile

from adbwrapper import ADB

from . import logs

logger = logging.getLogger(__name__)


class Driver:

    def __init__(self):
        """Init adb and command.

        export CLASSPATH=/data/local/od.zip;
        app_process /system/bin org.cf.oracle.Driver
        @/data/local/od-targets.json;
        """
        self.cmd_dss = ['am', 'broadcast', '-a', 'dss']
        self.cmd_set_new = ['setprop', 'dss.is.new', 'Yes']
        self.cmd_get_finish = ['getprop', 'dss.is.finish']
        self.cmd_set_finish = ['setprop', 'dss.is.finish', 'No']

        self.adb = ADB()
        self.adb.shell_command(self.cmd_set_new)

    def push_to_dss(self, apk_path):
        self.adb.run_cmd(['push', apk_path, '/data/local/dss/tmp.apk'])

    def decode(self, targets):
        self.adb.run_cmd(['push', targets, '/data/local/od-targets.json'])
        self.adb.shell_command(self.cmd_set_finish)
        self.adb.shell_command(self.cmd_dss)

        import time
        while 1:
            time.sleep(3)
            self.adb.shell_command(self.cmd_get_finish)
            output = self.adb.get_output().decode('utf-8', errors='ignore')
            if 'Yes' in output:
                break

        tempdir = tempfile.gettempdir()
        output_path = os.path.join(tempdir, 'output.json')
        self.adb.run_cmd(['pull', '/data/local/od-output.json', output_path])

        with open(output_path, mode='r+', encoding='utf-8') as ofile:
            size = len(ofile.read())
            if not size:
                self.adb.run_cmd(
                    ['pull', '/data/local/od-exception.txt', 'exception.txt'])
                self.adb.shell_command(['rm', '/data/local/od-exception.txt'])
            else:
                ofile.seek(0)
                result = json.load(ofile)

        if not logs.DEBUG:
            self.adb.shell_command(['rm', '/data/local/od-output.json'])
            self.adb.shell_command(['rm', '/data/local/od-targets.json'])
        else:
            self.adb.shell_command(['pull', '/data/local/od-targets.json'])
        os.unlink(output_path)

        self.adb.shell_command(['rm', '/data/local/dss/tmp.apk'])

        return result
