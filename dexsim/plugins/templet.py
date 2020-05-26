import hashlib
import logging
import os
import re
from json import JSONEncoder

import yaml
from smaliemu.emulator import Emulator

from dexsim import logs
from dexsim.plugin import Plugin

PLUGIN_CLASS_NAME = "TEMPLET"


class TEMPLET(Plugin):
    """
    模板匹配

    利用模板快速解密常见的解密方法
    模板包含：参数、解密方法、返回值处理
    """
    name = "TEMPLET"
    enabled = True
    tname = None
    index = 2

    def __init__(self, driver, smalidir):
        Plugin.__init__(self, driver, smalidir)
        # self.results = {}  # 缓存解密结果
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

                    if logs.isdebuggable:
                        print('Load ' + self.tname)
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
                        # print('>>>', result)
                        if not result:
                            continue
                        arguments = result[0]
                        argumentTypes = result[1]
                    else:
                        arguments = []  # 无参
                    # print(cls_name, mtd_name, arguments, argumentTypes)
                    data = {
                        'className': cls_name,
                        'methodName': mtd_name,
                        'arguments': arguments,
                        # TODO
                        # 建议内置固定的类型
                        # INT FLOAT STRING INT_ARRAY BYTE_ARRAY
                        #
                        'argumentTypes': argumentTypes,
                    }

                    data_id = hashlib.sha256(JSONEncoder().encode(
                        data).encode('utf-8')).hexdigest()

                    if data_id in self.results:
                        # print('{} 已解密 {}'.format(data_id, self.results.get(data_id)))
                        self.append_context(data_id, mtd, old_content, rtn_name)
                        continue

                    # 单次解密非常快
                    # 直接哈希化，保存结果。
                    result = self.driver.rpc_static_method(data)
                    print(result)
                    self.results[data_id] = result
                    # print('{} 解密为 {}'.format(data_id, result))

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
        '''
        生成解密函数的参数列表，传给DSS，格式为：
        "arguments": ["I:198", "I:115", "I:26"]
        '''
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
            # print("?????", item, result)
            if result is None:
                # 说明类型不支持
                return ([], [])
            argumentType, argument = result.split(':')
            # print(argument, argumentType)
            arguments.append(argument)
            argumentTypes.append(argumentType)

        if len(arguments) == len(protos):
            return (arguments, argumentTypes)

