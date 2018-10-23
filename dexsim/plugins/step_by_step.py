#
# 本模块超级耗时，建议删除不必要的类，再开启本插件进行解密。
#


import ast
import logging
import os
import re
import tempfile
from json import JSONEncoder

import yaml
from colorclass.color import Color
from smafile import SmaliLine, java2smali, smali2java
from smaliemu.emulator import Emulator
from timeout3 import TIMEOUT_EXCEPTION

from dexsim import logs
from dexsim.plugin import Plugin

PLUGIN_CLASS_NAME = "STEP_BY_STEP"

logger = logging.getLogger(__name__)

android_strs = [
    'Ljava/lang/System;', 'Landroid/os/Environment'
]


class STEP_BY_STEP(Plugin):
    '''
    这个插件只能执行一次

    它的替换方式，是在原有的代码上直接添加内容。
    不会替换掉原来的方法。
    如果继续执行，会导致无限循环。
    '''
    name = "STEP_BY_STEP"
    enabled = False
    tname = None
    index = 4
    ONE_TIME = False  # 表示该插件只执行一次

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
                if logs.isdebuggable:
                    print(mtd)
                # if 'com/android/internal/wrapper/NativeWrapper;->' not in str(mtd):
                #     continue
                # if 'eMPGsXR()Ljava/lang/Class;' not in str(mtd):
                #     continue
                if logs.isdebuggable:
                    print(Color.red(mtd))
                if self.skip_mtd(mtd):
                    continue
                self._process_mtd(mtd)

        # 强制更新
        for sf in self.smalidir:
            sf.update()

    def skip_mtd(self, mtd):
        """跳过不需要处理的方法：
        [x] 跳过构造函数<init>、静态初始化函数<clinit>
        [x] 无静态解密函数
        TODO [ ] 字符串类函数，需要具体

        Args:
            mtd (SmaliMethod): Smali方法对象

        Returns:
            bool: True 表示跳过，False 表示不跳过。

        """
        '''
        跳过不需要处理的函数
        '''
        mset = {'<clinit>', '<init>'}
        if mtd.get_name() in mset:
            return True

        # 判断方法体内是否存在可以解密的函数
        # 1. func
        # 2. string相关函数
        if self.invoke_static_ptn.search(mtd.get_body()):
            return False

        if self.new_string_ptn.search(mtd.get_body()):
            return False

        return True

    @staticmethod
    def process_invoke_static_statement(line):
        """处理invoke static语句，获取解密函数相关信息

        Args:
            line (str): Description of parameter `line`.

        Returns:
            tupple: None 表示跳过，非None（类名、方法名、参数类型、返回值类型、参数寄存器） 表示不跳过。

        """
        # 获取函数相关信息
        cname, mname, ptypes, rtype, rnames = SmaliLine.parse(line)

        # 调用类
        if cname in {'Ljava/lang/reflect/Method;', 'Ljava/lang/String;'}:
            return

        # 返回值如果为对象，那么不能为非字符串类型
        if rtype[0] == 'L' and rtype != 'Ljava/lang/String;':
            return

        if rtype in ['V', 'Z']:
            return

        # 解密参数
        # TODO 也许可以指定任意参数，目前暂时不支持。
        itypes = set(ptypes) & {
            'Landroid/content/Context;', 'Landroid/app/Activity;', 'Ljava/lang/Throwable;'}
        if itypes:
            return

        return cname, mname, ptypes, rtype, rnames

    def process_xget_statement(self, line):
        """处理opcode形如*get相关的语句，如sget、iget等。
        这类语句通常都是从类的字段中获取值。
        iget-object v3, p0, La/b/c/d;->q:Ljava/lang/String;

        Args:
            line (str): smali语句

        Returns:
            None:

        """
        desc = line.split()[-1]  # La/b/c/d;->q:Ljava/lang/String;
        if desc in self.fields:
            return
        cname, fname, rtype, rname = SmaliLine.parse(line)

        types = {
            'B', 'S', 'C', 'I', 'J', 'F', 'D', 'Ljava/lang/String;',
            '[B', '[S', '[C', '[I', '[J', '[F', '[D', '[Ljava/lang/String;'
        }
        if rtype not in types:
            return

        self.json_list = {
            'type': 'field',
            'data': []
        }
        json_item = {
            'className': cname,
            'fieldName': [fname]
        }
        self.json_list['data'].append(json_item)
        result = self.get_field_value()
        if logs.isdebuggable:
            print('FeildValue:', result)
        if not result:
            return
        value = result[fname]

        if rtype in {'B', 'S', 'C', 'I', 'J', 'F', 'D'}:
            value = int(value)
        elif rtype.startswith('['):
            value = ast.literal_eval(value)
        self.fields[desc] = value

    def _process_mtd(self, mtd):
        if logs.isdebuggable:
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

        xget_opcodes = {'iget', 'iget-object', 'sget', 'sget-object'}

        block_args = {'first': {}}  # 保存所有分支的执行结果
        last_block_key = 'first'  # 上一个分支-关键字
        this_block_key = 'first'  # 当前分支，默认第一分支
        keys = ['first']  # 默认执行第一分支

        for line in lines:
            index += 1
            if not line:
                continue
            new_body.append(line)  # 解密结果，直接放后面即可

            if logs.isdebuggable:
                print(Color.blue(line))

            parts = line.split()
            opcode = parts[0]

            # smali 代码分块执行
            # 命中下述关键字，则表示当前分支结束
            # 并根据上一个分支的情况，判断之前的分支是否可用
            if 'if-' in opcode:
                if logs.isdebuggable:
                    print('>' * 10, opcode)
                    print('this_block_key', this_block_key)
                    print('last_block_key', last_block_key)
                    print('block_args', block_args)

                # 存在两种情况
                # 1. 当前代码片段(if语句之前的代码)，还没执行；全部执行一次
                # 2. 当前代码片段，已经执行了一部分，因为解密；从执行后的地方开始执行

                pre_args = {}
                if this_block_key in last_block_key:
                    for key in reversed(keys):
                        if this_block_key not in key:
                            pre_args = block_args[key].copy()
                            break
                else:
                    pre_args = block_args[last_block_key].copy()

                if this_block_key in block_args:
                    pre_args.update(block_args[this_block_key])

                snippet.extend(array_data_content)
                self.emu.call(snippet, args=pre_args, cv=True, thrown=False)
                block_args[this_block_key] = self.emu.vm.variables
                snippet.clear()

                last_block_key = this_block_key
                this_block_key = 'if' + parts[-1]  # 表示接下来跑的代码块是这个语句的
                keys.append(this_block_key)

                if logs.isdebuggable:
                    print('block_args - 运行后', block_args)
                continue
            elif 'goto' in opcode:
                # 跳转语句，直接跳过
                continue
            elif opcode.startswith(':cond_')\
                or opcode.startswith(':try_start')\
                    or opcode.startswith('.catch_'):
                if logs.isdebuggable:
                    print('>' * 10, opcode)
                    print('this_block_key', this_block_key)
                    print('last_block_key', last_block_key)
                    print('block_args', block_args)
                # 存在两种情况
                # 1. 当前代码片段，还没执行；全部执行一次
                # 2. 当前代码片段，已经执行了一部分，因为解密；从执行后的地方开始执行
                pre_args = block_args[last_block_key].copy()
                if this_block_key in block_args:
                    pre_args.update(block_args[this_block_key])

                snippet.extend(array_data_content)
                self.emu.call(snippet, args=pre_args, cv=True, thrown=False)
                block_args[this_block_key] = self.emu.vm.variables

                snippet.clear()

                last_block_key = this_block_key
                this_block_key = opcode  # 表示接下来跑的代码块是这个语句的
                keys.append(this_block_key)

                if logs.isdebuggable:
                    print('block_args - 运行后', block_args)
                continue
            elif opcode.startswith(':try_start'):
                pass
            elif '.catch_' in opcode:
                # 前面代码当成一块处理
                continue

            snippet.append(line)

            is_static = True
            if opcode == 'invoke-static':
                result = self.process_invoke_static_statement(line)
                if result:
                    cname, mname, ptypes, rtype, rnames = result
                else:
                    continue
            # elif opcode == 'invoke-virtual':
            # TODO 实例方法，目前只考虑无参实例化。
            #     result = self.process_invoke_static_statement(line)
            #     if result:
            #         cname, mname, ptypes, rtype, rnames = result
            #         print(result)
            #         # 判断类的构造函数是否为<init>()V
            #         clz = self.smalidir.get_method(
            #             java2smali(cname), '<init>()V')
            #         if not clz:
            #             continue
            #         is_static = False
            #     else:
            #         continue
            elif opcode in xget_opcodes:
                self.process_xget_statement(line)
                continue
            elif 'Ljava/lang/String;-><init>([B)V' in line:
                if 'move-result-object' in snippet[0]:
                    snippet = snippet[1:]
                self.emu.call(snippet, args=args, cv=True, thrown=False)
                if not self.emu.vm.result:
                    continue

                # 如果有结果，则替换
                vx, _ = SmaliLine.parse(line)
                new_line = 'const-string {}, "{}"'.format(
                    vx, self.emu.vm.result)
                del new_body[-1]
                new_body.append(new_line)
                self.make_changes = True
                mtd.set_modified(True)

                snippet.clear()
                continue
            else:
                continue

            # 模拟执行，获取解密参数
            del snippet[-1]
            snippet.extend(array_data_content)
            try:
                snippet = self.process_if_statement(snippet)

                if logs.isdebuggable:
                    print(Color.red('开始处理解密参数 {}'.format(line)))
                    for l in snippet:
                        print(Color.red(l))

                    print('args', args)
                    print(block_args)
                    print(keys)
                    print(this_block_key)
                    print('-' * 80)

                pre_args = block_args[last_block_key].copy()
                args.update(pre_args)
                if this_block_key in block_args:
                    args.update(block_args[this_block_key])
                args.update(self.fields)

                self.emu.call(snippet, args=args, cv=True, thrown=False)
                registers = self.emu.vm.variables
                block_args[this_block_key] = registers

                if logs.isdebuggable:
                    print(snippet)
                    print('args:', args)
                    print('smali执行后，寄存器内容', registers)

                if registers:
                    for k, v in registers.items():
                        if v is None:
                            continue
                        args[k] = v

                registers = args
            except TIMEOUT_EXCEPTION:
                snippet.clear()
                continue

            print(Color.red('->'))

            obj_flag = False
            if len(ptypes) == 1 and ptypes[0][0] == 'L' and ptypes != ['Ljava/lang/String;']:
                # 单独处理参数为对象的情况
                obj_flag = True

            snippet.clear()  # 已经执行过的代码，不再执行
            if not registers and not obj_flag:
                continue

            print(Color.red('->>'))

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
                arguments.append('Object:' + smali2java(ptypes[0]))

            if logs.isdebuggable:
                print(Color.red('->>'))
                print('参数类型', ptypes)
                print('参数值', arguments)
            if len(arguments) != len(ptypes):
                print(Color.red('->> 参数对不上'))
                continue

            json_item = self.get_json_item(cname, mname, arguments)
            print(json_item)
            # print('生成json item')

            # {id}_{rtn_name} 让这个唯一化，便于替换
            old_content = '# %s' % json_item['id']
            # 如果 move_result_obj 操作存在的话，解密后一起替换
            find = self.move_result_obj_ptn.search(lines[index + 1])

            print(Color.red('->> not fount'))

            # 必须要找到返回值操作，用于更新寄存器
            if not find:
                print('找不到返回寄存器')
                continue

            print(Color.red('->>>'))

            rtn_name = find.groups()[0]
            # 为了避免 '# abc_v10' 替换成 '# abc_v1'
            old_content = old_content + '_' + rtn_name + 'X'
            self.append_json_item(json_item, mtd, old_content,
                                  rtn_name)

            result = self.get_result(rtype)
            if logs.isdebuggable:
                print("解密结果", result)

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
                mtd.set_modified(True)
            elif rtype.startswith('['):
                args[rtn_name] = result
                # 把结果保存到当前分支

            else:
                print("返回值并非字符串，也不是B/C数组")

            if args:
                block_args[this_block_key].update(args)

            # 把结果保存到当前分支
            if logs.isdebuggable:
                print(block_args)
                print('*' * 100)
            #     print('last_block_key', last_block_key)
            #     print('this_block_key', this_block_key)
            #
            # pre_args = block_args[last_block_key].copy()
            # if this_block_key in block_args:
            #     pre_args.update(block_args[this_block_key])
            # block_args[this_block_key] =

        mtd.set_body('\n'.join(new_body))

    @classmethod
    def process_if_statement(cls, snippet):
        '''处理if语句

        Arguments:
            snippets {list} -- small 代码
        '''
        ifreg = r'if-.*?:(cond_\w+).*?\1\n'
        ptn = re.compile(ifreg, flags=re.DOTALL)
        code_block = '\n'.join(snippet)
        return ptn.sub('', code_block).split('\n')

    def get_field_value(self):
        """动态获取Field的值

        Returns:
            type: 数值、字符串、数值列表、字符串列表
        """
        if not self.json_list:
            return

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
        """获取解密结果

        Args:
            rtype (String): 说明解密的类型

        Returns:
            type: 返回指定类型的解密结果

        """
        if not self.json_list:
            return

        jsons = JSONEncoder().encode(self.json_list)

        outputs = {}
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tfile:
            tfile.write(jsons)
        outputs = self.driver.decode(tfile.name)
        os.unlink(tfile.name)

        if not outputs:
            return False

        if rtype.startswith('['):
            return ast.literal_eval(outputs)

        if rtype == 'Ljava/lang/String;':
            print(outputs)

        return outputs
