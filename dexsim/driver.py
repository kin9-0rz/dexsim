import json
import logging
import os
import tempfile

from adbwrapper import ADB

from . import logs

logger = logging.getLogger(__name__)


DSS_PATH = '/data/local/dss'
DSS_APK_PATH = '/data/local/dss/tmp.apk'
DSS_DATA_PATH = '/data/local/dss_data'
DSS_OUTPUT_PATH = '/data/local/dss_data/od-output.json'
DSS_TARGETS_PATH = '/data/local/dss_data/od-targets.json'
DSS_EXCEPTION_PATH = '/data/local/dss_data/od-targets.json'


class Driver:

    def __init__(self):
        """Init adb and command.

        export CLASSPATH=/data/local/od.zip;
        app_process /system/bin org.cf.oracle.Driver
        @/data/local/od-targets.json;
        """
        self.cmd_dss_start = ['am', 'startservice',
                              'me.mikusjelly.dss/.DSService']
        self.cmd_dss_stop = ['am', 'force-stop', 'me.mikusjelly.dss']
        self.cmd_dss = ['am', 'broadcast', '-a', 'dss.start']

        self.cmd_get_finish = ['cat', '/data/local/dss_data/finish']
        self.cmd_set_finish = ['echo', 'No', '>',
                               '/data/local/dss_data/finish']
        self.cmd_set_new = ['echo', 'Yes', '>', '/data/local/dss_data/new']

        self.adb = ADB()
        self.adb.shell_command(self.cmd_set_new)

    def start_dss(self):
        self.adb.shell_command(self.cmd_dss_start)

    def stop_dss(self):
        self.adb.shell_command(self.cmd_dss_stop)

    def push_to_dss(self, apk_path):
        self.adb.run_cmd(['push', apk_path, DSS_APK_PATH])
        self.start_dss()

    def decode(self, targets):
        self.adb.run_cmd(['push', targets, DSS_TARGETS_PATH])
        self.adb.shell_command(self.cmd_set_finish)
        self.adb.shell_command(self.cmd_dss)

        print("debug .... test...")

        import time
        while 1:
            time.sleep(3)
            self.adb.shell_command(self.cmd_get_finish)
            output = self.adb.get_output().decode('utf-8', errors='ignore')
            if 'Yes' in output:
                break

        tempdir = tempfile.gettempdir()
        output_path = os.path.join(tempdir, 'output.json')
        self.adb.run_cmd(
            ['pull', DSS_OUTPUT_PATH, output_path])

        with open(output_path, mode='r+', encoding='utf-8') as ofile:
            size = len(ofile.read())
            if not size:
                self.adb.run_cmd(['pull', DSS_EXCEPTION_PATH, 'exception.txt'])
                self.adb.shell_command(['rm', DSS_EXCEPTION_PATH])
            else:
                ofile.seek(0)
                result = json.load(ofile)

        if not logs.DEBUG:
            self.adb.shell_command(['rm', DSS_OUTPUT_PATH])
            self.adb.shell_command(['rm', DSS_TARGETS_PATH])
        else:
            self.adb.shell_command(['pull', DSS_TARGETS_PATH])
        os.unlink(output_path)

        return result
