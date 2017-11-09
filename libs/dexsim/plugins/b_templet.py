import logging
import os
import re
from time import clock

import yaml
from smaliemu.emulator import Emulator

from libs.dexsim.plugin import Plugin

__all__ = ["TEMPLET"]

logger = logging.getLogger(__name__)


class TEMPLET(Plugin):
    """
    模板匹配

    利用模板快速解密常见的解密方法
    模板包含：参数、解密方法、返回值处理
    """
    name = "TEMPLET"
    enabled = True
    tname = None

    def __init__(self, driver, methods, smalidir):
        Plugin.__init__(self, driver, methods, smalidir)
        self.emu2 = Emulator()
        self.templets = []
        if not self.templets:
            self._init_templets()

    def _init_templets(self):
        templets_path = os.path.dirname(__file__)[:-7] + 'templets'
        for filename in os.listdir(templets_path):
            file_path = os.path.join(templets_path, filename)
            with open(file_path, encoding='utf-8') as f:
                self.templets.append(yaml.load(f.read()))

    def run(self):
        print('Run ' + __name__, end=' ', flush=True)
        for templet in self.templets:
            for item in templet:
                for key, value in item.items():
                    dtype = value['type']
                    if dtype != 1:
                        continue

                    self.tname = key
                    if not value['enabled']:
                        continue
                    logger.debug('Load ' + self.tname)
                    if value['protos']:
                        protos = [i.replace('\\', '')
                                  for i in value['protos']]
                    else:
                        protos = []

                    ptn = ''.join(value['pattern'])

                    self.__process(protos, ptn)

    def __process(self, protos, pattern):
        prog = re.compile(pattern)

        arr_data_prog = re.compile(self.ARRAY_DATA_PATTERN)

        for sf in self.smalidir:
            for mtd in sf.get_methods():
                array_data_content = []
                result = arr_data_prog.search(mtd.get_body())
                if result:
                    array_data_content = re.split(r'\n\s', result.group())

                for i in prog.finditer(mtd.get_body()):

                    old_content = i.group()
                    groups = i.groups()

                    cls_name = groups[-3][1:].replace('/', '.')
                    mtd_name = groups[-2]
                    rtn_name = groups[-1]

                    snippet = re.split(r'\n\s', old_content)[:-2]

                    snippet.extend(array_data_content)

                    # 执行解密方法之前的代码，获得各个寄存器的值
                    # 这里有一个问题，之前已经执行过的代码，为什么还要执行？
                    self.emu.call(snippet, thrown=False)

                    rnames = self.get_arguments_name(old_content, groups[-4])

                    arguments = self.get_arguments_1(
                        protos, rnames, self.emu.vm.variables)

                    if not arguments:
                        continue

                    json_item = self.get_json_item(
                        cls_name, mtd_name, arguments)

                    self.append_json_item(
                        json_item, mtd, old_content, rtn_name)

        self.optimize()
        self.clear()

    @staticmethod
    def get_arguments_name(line, result):
        """
        获取解密方法的参数名
        """
        # invoke-static {v14, v16} => [v14, v16]
        if 'range' not in line:
            return result.split(', ')

        # invoke-static/range {v14 .. v16} => [v14, v15, v16]
        args_names = []
        tmp = re.match(r'v(\d+).*?(\d+)', result)
        if not tmp:
            return
        start, end = tmp.groups()
        for rindex in range(int(start), int(end) + 1):
            args_names.append('v' + str(rindex))

        return args_names

    def get_arguments_1(self, protos, rnames, registers):
        '''
        xx
        '''
        # 参数获取 "arguments": ["I:198", "I:115", "I:26"]}
        arguments = []
        ridx = -1
        for item in protos:
            ridx += 1
            rname = rnames[ridx]
            if rname not in registers:
                break
            value = registers[rnames[ridx]]
            argument = self.convert_args(item, value)
            if argument is None:
                break
            arguments.append(argument)

        if len(arguments) == len(protos):
            return arguments
