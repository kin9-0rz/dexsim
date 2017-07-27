import os
import re

from smafile import SmaliFile
from .plugin_manager import PluginManager


class Oracle:

    def __init__(self, smali_dir, driver, include_str):

        self.driver = driver
        self.smali_files = self.__parse_smali(smali_dir)
        self.methods = self.__filter_methods(include_str)

        self.plugin_manager = PluginManager(self.driver, self.methods,
                                            self.smali_files)

    def __parse_smali(self, smali_dir):
        smali_files = []
        for parent, dirnames, filenames in os.walk(smali_dir):
            for filename in filenames:
                if filename.endswith('.smali'):
                    filepath = os.path.join(parent, filename)
                    smali_files.append(SmaliFile(filepath))
        return smali_files

    def __filter_methods(self, include_str):
        mtds = []
        for smali_file in self.smali_files:
            for mtd in smali_file.methods:

                if include_str and include_str in mtd.descriptor:
                    mtds.append(mtd)
                else:
                    mtds.append(mtd)

        return mtds

    def divine(self):
        plugins = self.plugin_manager.get_plugins()

        flag = True
        # smali methods which have been changed
        smali_mtds = set()
        while flag:
            flag = False
            for plugin in plugins:
                plugin.run()
                smali_mtds = smali_mtds.union(plugin.smali_mtd_updated_set)
                print(plugin.make_changes)
                flag = flag | plugin.make_changes
                plugin.make_changes = False

        ptn1 = (r'const-string.*?(v\d+), ".*?"\s*'
                r'(const-string.*?(v\d+), ".*?"\s*)')
        prog1 = re.compile(ptn1)

        ptn2 = r'(const-string.*?v\d+, ".*?"\s*)+move-result-object v\d+'
        prog2 = re.compile(ptn2)

        for smali_file in self.smali_files:
            for mtd in smali_file.methods:
                if mtd.descriptor in smali_mtds:
                    results = prog2.finditer(mtd.body)
                    for item in results:
                        arr = item.groups()
                        mtd.body = mtd.body.replace(item.group(), arr[0])
                        mtd.modified = True

                    results = prog1.finditer(mtd.body)
                    for item in results:
                        arr = item.groups()
                        if arr[0] == arr[2]:
                            mtd.body = mtd.body.replace(item.group(), arr[1])
                            mtd.modified = True

            smali_file.update()
