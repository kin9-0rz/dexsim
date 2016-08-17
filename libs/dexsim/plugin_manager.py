import os
import sys
from imp import find_module, load_module, acquire_lock, release_lock
import importlib

from .plugin import Plugin


class PluginManager(object):

    plugin_dir = 'plugins'

    def __init__(self, driver, methods, smali_files):
        self.driver = driver
        self.methods = methods
        self.smali_files = smali_files

        self.plugin_filenames = self.__get_plugin_filenames()
        self.__plugins = []
        self.__init__plugins()

    def get_plugins(self, ):
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
        return names

    def __init__plugins(self):
        for path in sys.path:
            if path and path in __file__:
                pkg = __file__.replace(path, '')
                break
        module_path = os.path.dirname(pkg)[1:].replace(os.sep, '.') + '.' + self.plugin_dir + '.'

        for name in self.plugin_filenames:
            spec = importlib.util.find_spec(module_path + name)  # (name, loader, origin)

            mod = spec.loader.load_module()
            for attrname in mod.__all__:
                clazz = getattr(mod, attrname)
                if not issubclass(clazz, Plugin):
                    continue
                self.__plugins.append(clazz(self.driver, self.methods, self.smali_files))
