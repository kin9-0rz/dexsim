from smafile import SmaliDir

from . import FILTERS
from .plugin_manager import PluginManager


class Oracle:

    def __init__(self, smali_dir, driver, includes):
        '''
        Lcom/a/b
        Lcom/a/b;-b
        Lcom/La/b;
        La/b;
        '''
        self.driver = driver

        paths = []
        if includes:
            for item in includes:
                paths.append(item[1:].split(';')[0])

        self.smalidir = SmaliDir(smali_dir, include=paths, exclude=FILTERS)
        self.plugin_manager = PluginManager(self.driver, self.smalidir)

    def divine(self):
        plugins = self.plugin_manager.get_plugins()

        flag = True
        smali_mtds = set()  # 存放已被修改的smali方法
        while flag:
            flag = False
            for plugin in plugins:
                plugin.run()
                smali_mtds = smali_mtds.union(plugin.smali_mtd_updated_set)
                print(plugin.make_changes) # 如果代码优化了，这个值为True
                flag = flag | plugin.make_changes
                plugin.make_changes = False
