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
        self.cmd_stub = ['export', 'CLASSPATH=/data/local/od.zip;', 'app_process', '/system/bin', 'org.cf.oracle.Driver', '@/data/local/od-targets.json;']

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

        os.remove(merged_apk)
        os.remove(merged_dex)

    def decode(self, tmpfile):
        self.adb.run_cmd(['push', tmpfile, '/data/local/od-targets.json'])
        self.adb.shell_command(self.cmd_stub)

        output_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
        self.adb.run_cmd(['pull', '/data/local/od-output.json', output_file.name])

        result = ''
        try:
            output_file = open(output_file.name, encoding='utf-8')
            result = json.load(output_file)
        except Exception as e:
            print(e)
            import shutil
            shutil.copy(output_file.name, 'output.txt')
            self.adb.run_cmd(['pull', '/data/local/od-exception.txt', 'exception.txt'])
            self.adb.shell_command(['rm', '/data/local/od-exception.txt'])

        output_file.close()
        os.unlink(output_file.name)
        return result
