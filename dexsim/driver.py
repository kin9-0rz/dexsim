import json
import os
import tempfile

from dexsim import DEBUG_MODE
from pyadb3 import ADB

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
        self.adb.run_shell_cmd(self.cmd_set_new)

    def start_dss(self):
        self.adb.run_shell_cmd(self.cmd_dss_start)

    def stop_dss(self):
        self.adb.run_shell_cmd(self.cmd_dss_stop)

    def push_to_dss(self, apk_path):
        self.adb.run_cmd(['push', apk_path, DSS_APK_PATH])

    def decode(self, targets):
        '''
        推送解密配置到手机/模拟器，让DSS读取解密配置。
        '''
        self.adb.run_cmd(['push', targets, DSS_TARGETS_PATH])
        self.adb.run_shell_cmd(self.cmd_set_finish)
        self.adb.run_shell_cmd(self.cmd_dss)

        self.start_dss()

        import time
        counter = 0
        while 1:
            time.sleep(3)
            counter += 3
            self.adb.run_shell_cmd(self.cmd_get_finish)
            output = self.adb.get_output().decode('utf-8', errors='ignore')
            if 'Yes' in output:
                break

            if counter > 120:
                print("Time out")
                self.stop_dss()
                return

        tempdir = tempfile.gettempdir()
        output_path = os.path.join(tempdir, 'output.json')
        self.adb.run_cmd(
            ['pull', DSS_OUTPUT_PATH, output_path])

        if not os.path.exists(output_path):
            print('Could not pull the file {}'.format(output_path))
            self.stop_dss()
            return

        with open(output_path, mode='r+', encoding='utf-8') as ofile:
            size = len(ofile.read())
            if not size:
                self.adb.run_cmd(['pull', DSS_EXCEPTION_PATH, 'exception.txt'])
                self.adb.run_shell_cmd(['rm', DSS_EXCEPTION_PATH])
            else:
                ofile.seek(0)
                result = json.load(ofile)

        if not DEBUG_MODE:
            self.adb.run_shell_cmd(['rm', DSS_OUTPUT_PATH])
            self.adb.run_shell_cmd(['rm', DSS_TARGETS_PATH])
        else:
            self.adb.run_shell_cmd(['pull', DSS_TARGETS_PATH])
        os.unlink(output_path)

        self.stop_dss()

        return result
