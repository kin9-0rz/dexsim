import importlib
import os
import sys

from .plugin import Plugin


class PluginManager(object):

    plugin_dir = 'plugins'

    def __init__(self, driver, smalidir):
        self.driver = driver
        self.smalidir = smalidir

        self.plugin_filenames = self.__get_plugin_filenames()
        self.__plugins = []
        self.__init__plugins()

    def get_plugins(self):
        return self.__plugins

    def get_plugin(self, name):
        for plugin in self.__plugins:
            if plugin.name == name:
                return plugin
        return None

    def __get_plugin_filenames(self):
        names = []
        plugin_path = os.path.join(os.path.dirname(__file__), self.plugin_dir)
        for filename in os.listdir(plugin_path):
            if filename.endswith(".py") and filename != "__init__.py":
                names.append(filename[:-3])
        names.sort()
        return names

    def __init__plugins(self):
        for path in sys.path:
            if path and path in __file__:
                pkg = __file__.replace(path, '')
                break
        module_path = os.path.dirname(pkg)[1:].replace(
            os.sep, '.') + '.' + self.plugin_dir + '.'

        tmp = [None] * len(self.plugin_filenames)

        for name in self.plugin_filenames:
            spec = importlib.util.find_spec(module_path + name)
            mod = spec.loader.load_module()
            clazz = getattr(mod, mod.PLUGIN_CLASS_NAME)
            if not issubclass(clazz, Plugin):
                continue

            if not clazz.enabled:
                print("Don't load plugin", clazz.name)
                continue
            tmp[clazz.index] = clazz(self.driver, self.smalidir)

        for item in tmp:
            if item:
                self.__plugins.append(item)
