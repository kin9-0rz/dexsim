import re
import os
import sys
import tempfile
import subprocess
import json

from powerzip import PowerZip
from adbwrapper import ADB


class Driver:
    def __init__(self):
        self.adb = ADB()
        self.cmd_stub = ['export', 'CLASSPATH=/data/local/od.zip;', 'app_process', '/system/bin', 'org.cf.oracle.Driver']

    def install(self, target_dex):
        '''
            Merge driver(driver.dex) and target dex file to oracle-driver.dex, then push to /data/local/
        '''
        print('Merge driver(driver.dex) and %s to oracle-driver.dex' % target_dex)

        for path in sys.path:
            if path and path in __file__:
                root_path = path
                break

        dx_path = os.path.join(root_path, "res", 'dx-19.1.0.jar')
        driver_path = os.path.join(root_path, "res", 'driver.dex')

        merged_dex = 'merged.dex'
        cmd = "java -cp %s com.android.dx.merge.DexMerger %s %s %s" % (dx_path, merged_dex, target_dex, driver_path)
        subprocess.call(cmd, shell=True)
        print('Pushing merged driver to device ...')

        merged_apk = 'merged.apk'
        pzip = PowerZip(merged_apk)
        pzip.add('classes.dex', merged_dex)
        pzip.save(merged_apk)
        pzip.close()

        self.adb.run_cmd(['push', merged_apk, '/data/local/od.zip'])
        print(self.adb.get_output())

        # os.remove(merged_dex.name)
        # os.remove(tmp_zip.name)

    def decode(self, tmpfile):
        print(tmpfile, "push ---->>>>>")
        self.adb.run_cmd(['push', tmpfile, '/data/local/od-targets.json'])
        print(self.adb.get_output())
        self.cmd_stub.append('@/data/local/od-targets.json;')
        self.adb.shell_command(self.cmd_stub)
        print(self.adb.get_output())

        output_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
        print(output_file.name, "test , NamedTemporaryFile")
        # self.adb.run_cmd(['pull', '/data/local/od-output.json', output_file.name])
        self.adb.run_cmd(['pull', '/data/local/od-output.json', 'result.json'])
        print(self.adb.get_output())
        # print('>>>>', output_file.name)

        try:
            output_file = open('result.json')
            # s = json.load(output_file)
            s = json.load(output_file)
            output_file.close()
            # os.unlink(output_file.name)
            return s
        except FileNotFoundError:
            self.adb.shell_command(['cat', '/data/local/od-exception.txt'])
            # self.adb.shell_command(['rm', '/data/local/od-exception.txt'])
            # os.unlink(output_file.name)
            return ''
