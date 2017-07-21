import os
import re
from queue import Queue

from smafile import SmaliFile
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
        smali_mtds = set()
        while flag:
            flag = False
            for plugin in plugins:
                plugin.run()
                smali_mtds = smali_mtds.union(plugin.smali_mtd_updated_set)
                print(plugin.make_changes)
                flag = flag | plugin.make_changes
                plugin.make_changes = False

        return

        line_queue = Queue(maxsize = 4)
        command_set = set()

        const_ptn = r'(const.*?),.*$'
        const_prog = re.compile(const_ptn)

        # 如果上一行是const，而下一行是move-result-object，则删除
        flag = False
        start = 0
        end = 0
        move_line = None

        for smali_file in self.smali_files:
            for mtd in smali_file.methods:
                if mtd.descriptor in smali_mtds:
                    body_tmp = mtd.body
                    lines = re.split(r'\n', mtd.body)
                    lines_copy = lines.copy()
                    lines.reverse()

                    counter = 0
                    for line in lines:
                        counter += 1

                        print(counter, bytearray(line, encoding='utf-8'))

                        if 'move-result-object' in line:
                            if lines[counter].startswith('const-string'):
                                print('>' * 80)
                                if line in lines_copy:
                                    print('???')
                                    print(bytearray(lines_copy[len(lines_copy)-counter], encoding='utf-8'))
                                    del lines_copy[len(lines_copy)-counter]
                                    print(bytearray(lines_copy[len(lines_copy)-counter], encoding='utf-8'))
                                    print('???')
                                # lines_copy.remove(line)
                            continue

                        results = const_prog.findall(line)
                        if not results:
                            continue
                        command = results[0]
                        if command in command_set:
                            lines_copy.remove(line)
                        if line_queue.full():
                            item = line_queue.get()
                            # 删除不必要的const语句（即解密参数）
                            if item in command_set:
                                command_set.remove(item)
                        line_queue.put(command)
                        command_set.add(command)

                    line_queue.queue.clear()
                    command_set.clear()
                    mtd.body = '\n'.join(lines_copy)
                    mtd.modified = True

            smali_file.update()
