import hashlib
import logging
import os
import re
from json import JSONEncoder

import yaml
from smaliemu.emulator import Emulator

from dexsim import var
from dexsim.plugin import Plugin

PLUGIN_CLASS_NAME = "TEMPLET"


class TEMPLET(Plugin):
    """
    模板匹配

    利用模板快速解密常见的解密方法
    模板包含：参数、解密方法、返回值处理
    解密常见的静态解密方法。
    """
    name = "TEMPLET"
    enabled = True
    tname = None
    index = 2

    def __init__(self, driver, smalidir):
        Plugin.__init__(self, driver, smalidir)
        self.emu2 = Emulator()
        self.templets = []
        if not self.templets:
            self._init_templets()

    def _init_templets(self):
        """初始化解密模版
        """        
        templets_path = os.path.dirname(__file__)[:-7] + 'templets'
        for filename in os.listdir(templets_path):
            file_path = os.path.join(templets_path, filename)
            with open(file_path, encoding='utf-8') as f:
                self.templets.append(
                    yaml.load(f.read(), Loader=yaml.SafeLoader))

    def run(self):
        print('运行插件' + __name__)

        for templet in self.templets:
            for item in templet:
                for key, value in item.items():
                    dtype = value['type']
                    if dtype != 1:
                        continue

                    self.tname = key
                    if not value['enabled']:
                        continue

                    if var.is_debug:
                        logging.info('加载模版 ' + self.tname)

                    if value['protos']:
                        protos = [i.replace('\\', '')
                                  for i in value['protos']]
                    else:
                        protos = []

                    ptn = ''.join(value['pattern'])

                    self.__process(protos, ptn)

        self.optimize()

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

                    # 模板主要用于获取类、方法、返回寄存器、参数寄存器（可能存在无参）
                    cls_name = groups[-3][1:].replace('/', '.')
                    mtd_name = groups[-2]
                    rtn_name = groups[-1]

                    if cls_name in ['java.lang.String']:
                        continue

                    # 由于参数的个数不一致，所以，不好直接获取，直接通过简单运算获取
                    snippet = re.split(r'\n\s', old_content)[:-2]
                    snippet.extend(array_data_content)
                    self.emu.call(snippet, thrown=False)

                    arguments = []
                    argumentTypes = []

                    if protos:
                        # rnames 存放寄存器名
                        rnames = self.get_arguments_name(
                            old_content, groups[-4])
                        result = self.gen_arguments(
                            protos, rnames, self.emu.vm.variables)
                        if not result:
                            continue
                        arguments = result[0]
                        argumentTypes = result[1]
                    else:
                        arguments = []  # 无参

                    data = {
                        'className': cls_name,
                        'methodName': mtd_name,
                        'arguments': arguments,
                        'argumentTypes': argumentTypes,
                    }

                    data_id = hashlib.sha256(JSONEncoder().encode(
                        data).encode('utf-8')).hexdigest()

                    if self.results.get(data_id) == '解密失败':
                        continue

                    if data_id in self.results:
                        self.append_context(
                            data_id, mtd, old_content, rtn_name)
                        continue

                    result = self.driver.rpc_static_method(data)

                    if not result:
                        self.results[data_id] = '解密失败'
                        continue

                    logging.info('解密结果: ' + result)
                    self.results[data_id] = result
                    self.append_context(data_id, mtd, old_content, rtn_name)

    @staticmethod
    def get_arguments_name(line, result):
        '''获取参数寄存器

        Arguments:
            line {String} --
            result {String}} -- [description]

        Returns:
            [type] -- [description]
        '''

        """
        获取解密方法的寄存器名
        """
        # invoke-static {v14, v16} => [v14, v16]
        if 'range' not in line:
            return result.split(', ')

        # invoke-static/range {v14 .. v16} => [v14, v15, v16]
        args_names = []
        tmp = re.match(r'v(\d+) \.\. v(\d+)', result)
        if not tmp:
            return
        start, end = tmp.groups()
        for rindex in range(int(start), int(end) + 1):
            args_names.append('v' + str(rindex))

        return args_names

    def gen_arguments(self, protos, rnames, registers):
        """获取参数列表和参数类型列表

        Args:
            protos ([type]): protos
            rnames ([type]): 寄存器名，如v1，v2
            registers ([type]): 存放所有的寄存器的字典

        Returns:
            [type]: 参数列表、参数类型列表
        """        
        arguments = []
        argumentTypes = []
        if rnames is None:
            return (arguments, argumentTypes)

        ridx = -1
        for item in protos:
            ridx += 1
            rname = rnames[ridx]
            if rname not in registers:
                break
            value = registers[rnames[ridx]]
            result = self.convert_args(item, value)
            if result is None:
                # 说明类型不支持
                return ([], [])
            argumentType, argument = result.split(':')
            # print(argument, argumentType)
            arguments.append(argument)
            argumentTypes.append(argumentType)

        if len(arguments) == len(protos):
            return (arguments, argumentTypes)
