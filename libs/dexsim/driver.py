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
        self.cmd_stub = "export CLASSPATH=/data/local/od.zip; app_process /system/bin org.cf.oracle.Driver"

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

        merged_dex = tempfile.TemporaryFile()
        merged_dex.close()
        cmd = "java -cp %s com.android.dx.merge.DexMerger %s %s %s" % (dx_path, merged_dex.name, target_dex, driver_path)
        subprocess.call(cmd, shell=True)
        print('Pushing merged driver to device ...')

        tmp_zip = tempfile.TemporaryFile()
        tmp_zip.close()
        pzip = PowerZip(tmp_zip.name)
        pzip.add('classes.dex', merged_dex.name)
        pzip.save(tmp_zip.name)
        pzip.close()

        self.adb.run_cmd('push %s /data/local/od.zip' % tmp_zip.name)

        os.remove(merged_dex.name)
        os.remove(tmp_zip.name)

    def decode(self, tmpfile):
        self.adb.run_cmd('push %s /data/local/od-targets.json' % tmpfile)
        self.adb.shell_command(self.cmd_stub + ' @/data/local/od-targets.json;')

        output_file = tempfile.TemporaryFile(mode='w+', delete=False)
        self.adb.run_cmd('pull /data/local/od-output.json %s' % output_file.name)

        try:
            s = json.load(output_file)
            output_file.close()
            os.unlink(output_file.name)
            return s
        except FileNotFoundError:
            print(self.adb.shell_command('cat /data/local/od-exception.txt'))
            self.adb.shell_command('rm /data/local/od-exception.txt')
            os.unlink(output_file.name)
            return ''
