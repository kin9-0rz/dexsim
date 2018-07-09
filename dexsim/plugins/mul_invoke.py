#
# array.py
# @author mikusjelly
# @website http://mikusjelly.github.io
# @license MIT
# @description 处理多次调用函数的情况
# @created Tue Jun 12 2018 12:02:59 GMT+0800 (CST)
#


import logging
import os
import re

import yaml
from smaliemu.emulator import Emulator
from timeout3 import TIMEOUT_EXCEPTION

from ..plugin import Plugin

PLUGIN_CLASS_NAME = "MUL_INVOKE"

logger = logging.getLogger(__name__)

android_strs = [
    'Ljava/lang/System;', 'Landroid/os/Environment'
]


DEBUG = True


class MUL_INVOKE(Plugin):
    '''
    这个插件只能执行一次

    它的替换方式，是在原有的代码上直接添加内容。
    不会替换掉原来的方法。
    如果继续执行，会导致无限循环。
    '''
    name = "MUL_INVOKE"
    enabled = True
    tname = None
    index = 4
    ONE_TIME = False # 表示该插件只执行一次

    def __init__(self, driver, smalidir):
        Plugin.__init__(self, driver, smalidir)

        # 匹配参数为内置类型的静态调用函数
        INVOKE_STATIC_RE = (
            r'invoke-static.*?{([v\.\d,\s]*)}, (.*?);->(.*?)'
            r'\(((?:B|S|C|I|J|F|D|Ljava/lang/String;|'
            r'\[B|\[S|\[C|\[I|\[J|\[F|\[D|\[Ljava/lang/String;'
            r')*?)\)Ljava/lang/String;')

        # 任意静态调用函数
        ANY_INVOKE_STATIC_RE = (
            r'invoke-static.*?{([v\.\d,\s]*)}, (.*?);->(.*?)'
            r'\(((?:B|S|C|I|J|F|D|L.*?;|'
            r'\[B|\[S|\[C|\[I|\[J|\[F|\[D|\[Ljava/lang/String;'
            r')*?)\)(\[B|\[S|\[C|\[I|\[J|\[F|\[D|\[Ljava/lang/String;)')

        # 匹配proto
        PROTO_RE = (
            r'(B|S|C|I|J|F|D|Ljava/lang/String;|'
            r'\[B|\[S|\[C|\[I|\[J|\[F|\[D|\[Ljava/lang/String;)'
        )

        NEW_STRING = (
            r'invoke-direct {(v\d+), v\d+}, '
            r'Ljava/lang/String;-><init>\([\[BCI]+\)V'
        )

        self.invoke_static_ptn = re.compile(INVOKE_STATIC_RE)
        self.proto_ptn = re.compile(PROTO_RE)
        self.arr_data_ptn = re.compile(self.ARRAY_DATA_PATTERN)
        self.move_result_obj_ptn = re.compile(self.MOVE_RESULT_OBJECT)
        self.new_string_ptn = re.compile(NEW_STRING)
        self.any_invoke_static_ptn = re.compile(ANY_INVOKE_STATIC_RE)

    def run(self):
        if self.ONE_TIME:
            return
        print('Run ' + __name__, end=' ', flush=True)
        self.__process()
        self.ONE_TIME = True

    def __process(self):
        for sf in self.smalidir:
            for mtd in sf.get_methods():
                if self.skip_mtd(mtd):
                    continue
                self._process_mtd(mtd)
        # 强制更新
        for sf in self.smalidir:
            sf.update()

    def skip_mtd(self, mtd):
        '''
        跳过不需要处理的函数
        '''
        mset = set(['<clinit>', '<init>'])
        if mtd.get_name() in mset:
            return True

        # 判断方法体内是否存在可以解密的函数
        # 1. func
        # 2. string相关函数
        if not self.invoke_static_ptn.search(mtd.get_body()):
            if not self.new_string_ptn.search(mtd.get_body()):
                return True

    def _process_mtd(self, mtd):
        if DEBUG:
            from colorclass.color import Color
            print('\n', '+' * 100)
            print('Starting to decode ...')
            print(Color.green(mtd))
        # 如果存在数组
        array_data_content = []
        arr_res = self.arr_data_ptn.search(mtd.get_body())
        if arr_res:
            array_data_content = re.split(r'\n\s', arr_res.group())

        lines = re.split(r'\n\s*', mtd.get_body())

        old_body = lines.copy()  # 存放原始方法体
        new_body = []   # 存放解密后的方法体

        snippet = []  # 存放smali代码，用于模拟执行
        args = {}   # 存放方法参数，用于smaliemu执行

        index = -1  # 用于计数

        for line in lines:
            snippet.append(line)
            new_body.append(line)  # 解密结果，直接放后面即可

            index += 1
            if 'invoke-' not in line and 'iget-' not in line:
                continue

            from smafile import SmaliLine
            # 函数有两种类型：
            # 1. 字符串内置类型 - smaliemu能直接执行
            # 2. 其他类型 - 需要发射调用
            if DEBUG:
                print('LINE:', Color.red(line))

            if 'Ljava/lang/String;->' in line:
                if '<init>' not in line:
                    continue
                
                if DEBUG:
                    print(Color('{autoyellow}process new string...{/yellow} '))

                # 如果是字符串函数，参数为[B/[C/[I，则考虑
                rtn_name, rnames = SmaliLine.parse_string(line)
                if not rnames:
                    continue

                # 直接执行emu解密
                try:
                    ll = args[rnames[1]]
                    # print(ll)
                except KeyError:
                    continue

                if not isinstance(ll, list):
                    continue

                no_str = False
                for i in ll:
                    if i < 0:
                        no_str = True
                        break
                if no_str:
                    continue

                result = ''.join(chr(x) for x in ll)

                if DEBUG:
                    print(result)

                # 更新寄存器
                args[rtn_name] = result
                # 更新代码
                new_line = 'const-string {}, "{}"'.format(rtn_name, result)
                new_body = new_body[:-1]
                new_body.append(new_line)
                self.make_changes = True
                mtd.set_modified(True)
                continue

            elif 'invoke-static' in line:
                # 获取函数相关信息
                cname, mname, ptypes, rtype, rnames = SmaliLine.parse_invoke_static(
                    line)
                if cname in ['Ljava/lang/reflect/Method;']:
                    print(cname, 'will skip')
                    continue

                # 返回值不能其他引用类型
                if rtype[0] == 'L' and rtype != 'Ljava/lang/String;':
                    continue

                if rtype in ['V', 'Z']:
                    continue

                flagx = False
                for i in ['Landroid/content/Context;', 'Landroid/app/Activity;']:
                    if i in ptypes:
                        flagx = True
                        break

                if flagx:
                    continue
            elif 'iget-object' in line:
                #  iget-object v3, p0, Lcom/fmsd/a/d;->q:Ljava/lang/String;
                # 这种情况，需要直接通过反射获取
                # clz_name, field_name, rname =
                cname, fname, rtype, rname = SmaliLine.parse_iget_object(line)
                if rtype != 'Ljava/lang/String;':
                    continue

                self.json_list = {
                    'type': 'field',
                    'data': []
                }
                json_item = {
                    'className': cname,
                    'fieldName': [fname]
                }
                # print(json_item)
                self.json_list['data'].append(json_item)

                result = self.get_field_value()
                if not result:
                    continue
                value = result[fname]
                args[rname] = value
                continue
            else:
                continue
            # print('>', cname)
            # print('>', mname)
            # print('>', ptypes)
            # print('>', rnames)
            # print(">", 'return Type:', rtype)
            # 参数名(寄存器的名)，类名，方法名，proto(简称)
            # register_name, class_name, mtd_name, ptypescc
            # ('v1, v2, v3', 'Lcom/game/pay/sdk/y', 'a', 'ISB')
            # 解密参数的寄存器名

            # 初始化所有寄存器
            del snippet[-1]
            snippet.extend(array_data_content)
            try:
                args.update(self.pre_process(snippet))
            except TIMEOUT_EXCEPTION:
                pass

            try:
                # for lx in snippet:
                #     print(lx)
                self.emu.call(snippet, args=args, cv=True, thrown=False)
                registers = self.emu.vm.variables
                # registers = self.get_vm_variables(snippet, args, rnames)
                # print('smali执行后，寄存器内容', registers)
                # args = registers if registers else args
                if registers:
                    for k, v in registers.items():
                        if v is None:
                            continue
                        args[k] = v
                
                registers = args
            except TIMEOUT_EXCEPTION:
                snippet.clear()

                continue

            # print('更新寄存器内容', args)
            # if not registers:
            #     registers = args

            obj_flag = False
            if len(ptypes) == 1 and ptypes[0][0] == 'L' and ptypes != ['Ljava/lang/String;']:
                # 单独处理参数为对象的情况
                obj_flag = True

            # 已经执行过的代码，不再执行
            snippet.clear()
            if not registers and not obj_flag:
                continue

            # print('----->>>>>>>>>>')
            # 从寄存器中获取对应的参数
            # 参数获取 "arguments": ["I:198", "I:115", "I:26"]}
            arguments = []
            # args = {}  # the parameter of smali method
            if not obj_flag:
                ridx = -1
                for item in ptypes:
                    ridx += 1
                    rname = rnames[ridx]
                    if rname not in registers:
                        break
                    value = registers[rnames[ridx]]
                    argument = self.convert_args(item, value)
                    if argument is None:
                        break
                    arguments.append(argument)
            else:
                arguments.append('Object:' + self.smali2java(ptypes[0]))

            # print('参数类型', ptypes)
            # print('参数值', arguments)

            if len(arguments) != len(ptypes):

                continue

            json_item = self.get_json_item(cname, mname, arguments)
            # print('生成json item')

            # {id}_{rtn_name} 让这个唯一化，便于替换
            old_content = '# %s' % json_item['id']
            # 如果 move_result_obj 操作存在的话，解密后一起替换
            find = self.move_result_obj_ptn.search(lines[index + 1])

            # 必须要找到返回值操作，用于更新寄存器
            if not find:
                # print('找不到返回寄存器')
                continue

            rtn_name = find.groups()[0]
            # 为了避免 '# abc_v10' 替换成 '# abc_v1'
            old_content = old_content + '_' + rtn_name + 'X'
            self.append_json_item(json_item, mtd, old_content,
                                  rtn_name)

            # print(json_item)
            result = self.get_result(rtype)
            # print("解密结果", result)

            self.json_list.clear()

            if result:
                new_body = new_body[:-1]
            else:
                continue

            if not args:
                args = {}
            if rtype == 'Ljava/lang/String;':
                result = list(result.values())[0][0]
                # 更新寄存器
                args[rtn_name] = result
                # 更新代码
                new_line = 'const-string {}, "{}"'.format(rtn_name, result)
                new_body.append(new_line)
                self.make_changes = True
                # print(args)
                mtd.set_modified(True)
            elif rtype.startswith('['):
                # print("返回值为数组，更新寄存器内容")
                # print(result)
                args[rtn_name] = result
                # print(args)
            else:
                print("返回值并非字符串，也不是B/C数组")

            # print('-' * 100)

        mtd.set_body('\n'.join(new_body))

    def get_field_value(self):
        """
        把Field的值，写回到smali中

        因为Field本来就是唯一，所以，不需要ID，一些繁琐的东西。
        """
        if not self.json_list:
            return

        from json import JSONEncoder
        import tempfile

        jsons = JSONEncoder().encode(self.json_list)
        self.json_list = []

        outputs = {}
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tfile:
            tfile.write(jsons)
        outputs = self.driver.decode(tfile.name)
        os.unlink(tfile.name)

        if not outputs:
            return False

        if isinstance(outputs, str):
            return False

        return list(outputs.values())[0]

    def get_result(self, rtype='Ljava/lang/String;'):
        if not self.json_list:
            return

        from json import JSONEncoder
        import tempfile

        jsons = JSONEncoder().encode(self.json_list)

        outputs = {}
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tfile:
            tfile.write(jsons)
        outputs = self.driver.decode(tfile.name)
        os.unlink(tfile.name)

        if not outputs:
            return False

        if rtype.startswith('['):
            import ast
            return ast.literal_eval(outputs)

        return outputs

    @staticmethod
    def smali2java(smali_clz):
        return smali_clz.replace('/', '.')[1:-1]

    @staticmethod
    def java2smali(java_clz):
        return 'L' + java_clz.replace('', '/') + ';'
