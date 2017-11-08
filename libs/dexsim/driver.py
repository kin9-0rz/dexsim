import os
import sys
import tempfile
import subprocess
import json
import logging

from powerzip import PowerZip
from adbwrapper import ADB

from libs.dexsim import logs

logger = logging.getLogger(__name__)


class Driver:

    def __init__(self):
        """Init adb and command.

        export CLASSPATH=/data/local/od.zip;
        app_process /system/bin org.cf.oracle.Driver
        @/data/local/od-targets.json;
        """
        self.adb = ADB()

        self.cmd_stub = ['export', 'CLASSPATH=/data/local/od.zip;',
                         'app_process', '/system/bin', 'org.cf.oracle.Driver',
                         '@/data/local/od-targets.json;']

    def install(self, target_dex):
        """Push target dex to device or emulator.

        Merge driver(driver.dex) and target dex file to oracle-driver.dex,
        then push to /data/local/
        """
        logger.info(
            'Merge driver(driver.dex) and %s to oracle-driver.dex', target_dex)

        for path in sys.path:
            if path and path in __file__:
                root_path = path
                break

        dx_path = os.path.join(root_path, "res", 'dx-19.1.0.jar')
        driver_path = os.path.join(root_path, "res", 'driver.dex')

        merged_dex = 'merged.dex'
        cmd = "java -cp %s com.android.dx.merge.DexMerger %s %s %s" % (
            dx_path, merged_dex, target_dex, driver_path)
        subprocess.call(cmd)
        logger.info('Pushing merged driver to device ...')

        merged_apk = 'merged.apk'
        pzip = PowerZip(merged_apk)
        pzip.add('classes.dex', merged_dex)
        pzip.save(merged_apk)
        pzip.close()

        self.adb.run_cmd(['push', merged_apk, '/data/local/od.zip'])

        os.remove(merged_apk)
        os.remove(merged_dex)

    def decode(self, targets):
        self.adb.run_cmd(['push', targets, '/data/local/od-targets.json'])
        self.adb.shell_command(self.cmd_stub)

        output = self.adb.get_output().decode('utf-8', errors='ignore')

        if 'success' not in output:
            # logger.info(output)
            return

        # try:
        #     logger.info(output)
        # except UnicodeEncodeError:
        #     logger.warning(str(output).encode('utf-8'))

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

        return result
