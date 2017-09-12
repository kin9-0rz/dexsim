import os

from smafile import SmaliFile, SmaliDir
from libs.dexsim.plugin_manager import PluginManager


class Oracle:

    def __init__(self, smali_dir, driver, include_str):

        self.driver = driver

        self.smalidir = SmaliDir(smali_dir)
        self.smali_files = self.__parse_smali(smali_dir)
        self.methods = self.__filter_methods(include_str)

        # self.plugin_manager = PluginManager(self.driver, self.methods,
        #                                     self.smali_files)
        self.plugin_manager = PluginManager(self.driver, self.methods,
                                            self.smalidir)

    def __parse_smali(self, smali_dir):
        smali_files = []
        for parent, _, filenames in os.walk(smali_dir):
            for filename in filenames:
                if filename.endswith('.smali'):
                    filepath = os.path.join(parent, filename)
                    sf = SmaliFile(filepath)
                    smali_files.append(sf)
        return smali_files

    def __filter_methods(self, include_str):
        mtds = []
        for smali_file in self.smali_files:
            for mtd in smali_file.get_methods():

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
