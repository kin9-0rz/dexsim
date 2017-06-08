import os

from smali_file import SmaliFile
from .plugin_manager import PluginManager


class Oracle:
    def __init__(self, smali_dir, driver, include_str):
        '''
            include_str 为过滤字符串
        '''
        self.driver = driver
        self.smali_files = self.__parse_smali(smali_dir)
        self.methods = self.__filter_methods(include_str)

        self.plugin_manager = PluginManager(self.driver, self.methods, self.smali_files)

    def __parse_smali(self, smali_dir):
        smali_files = []
        for parent, dirnames, filenames in os.walk(smali_dir):
            for filename in filenames:
                if filename.endswith('.smali'):
                    filepath = os.path.join(parent, filename)
                    smali_files.append(SmaliFile(filepath))
        return smali_files

    def __filter_methods(self, include_str):
        '''
        指定要解密的包/类/方法，None则跳过
        '''
        mtds = []
        for smali_file in self.smali_files:
            for mtd in smali_file.methods:

                if include_str and include_str in mtd.descriptor:
                    mtds.append(mtd)
                else:
                    mtds.append(mtd)

        return mtds

    def divine(self):
        '''
        运行插件，解密，更新内容，直到没有再可以更新的代码，则停止
        '''
        plugins = self.plugin_manager.get_plugins()

        flag = True
        while flag:
            flag = False
            for plugin in plugins:
                plugin.run()
                print(plugin.make_changes)
                flag = flag | plugin.make_changes
                plugin.make_changes = False
