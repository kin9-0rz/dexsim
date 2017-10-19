import re
import os
import yaml

from libs.dexsim.plugin import Plugin
from libs.dexsim.timeout import timeout
from libs.dexsim.timeout import TIMEOUT_EXCEPTION

__all__ = ["TEMPLET"]


class TEMPLET(Plugin):
    """Load templets to decode apk/dex."""
    name = "TEMPLET"
    enabled = True
    tname = None

    def __init__(self, driver, methods, smalidir):
        Plugin.__init__(self, driver, methods, smalidir)
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
        print('run Plugin: %s' % self.name)
        # 1. 使用参数 + 函数调用的方式处理 - 精准匹配 - 处理快
        for templet in self.templets:
            for item in templet:
                for key, value in item.items():
                    dtype = value['type']
                    if dtype != 1:
                        continue

                    self.tname = key
                    if not value['enabled']:
                        print('Not Load :', self.tname)
                        continue
                    print('Load :', self.tname)
                    if value['protos']:
                        protos = [i.replace('\\', '')
                                  for i in value['protos']]
                    else:
                        protos = []

                    ptn = ''.join(value['pattern'])

                    self.__process_quickly(protos, ptn)

        # 2. 使用通用的方式 - 处理比较慢
        for templet in self.templets:
            for item in templet:
                for key, value in item.items():
                    dtype = value['type']
                    if dtype != 2:
                        continue

                    self.tname = key
                    if not value['enabled']:
                        print('Not Load :', self.tname)
                        continue
                    print('Load :', self.tname)
                    if value['protos']:
                        protos = [i.replace('\\', '')
                                  for i in value['protos']]
                    else:
                        protos = []

                    ptn = ''.join(value['pattern'])

                    self.__process_slowly(protos, ptn)

    def get_clz_mtd_rtn_name(self, line):
        '''
            class_name, method_name, return_variable_name
        '''
        clz_name, mtd_name = re.search(
            r'invoke-static.*?{.*?}, (.*?);->(.*?)\(.*?\)Ljava/lang/String;', line).groups()
        clz_name = clz_name[1:].replace('/', '.')

        prog = re.compile(self.MOVE_RESULT_OBJECT)
        mro_statement = prog.search(line).group()
        rtn_name = mro_statement[mro_statement.rindex(' ') + 1:]
        return (clz_name, mtd_name, rtn_name)

    def __process_quickly(self, protos, pattern):
        '''模板中带参数，精准匹配，速度快。'''
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

                    self.emu.call(snippet, thrown=False)

                    rnames = self.get_rnames_1(old_content, groups[-4])

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

    def get_rnames_1(self, line, result):
        # register_names
        rnames = []
        # invoke - static {v14, v16},
        if 'range' not in line:
            rnames.extend(result.split(', '))
        elif 'range' in line:
            # invoke-static/range {v14 .. v16}
            tmp = re.match(r'v(\d+).*?(\d+)', result)
            if not tmp:
                return
            start, end = tmp.groups()
            for rindex in range(int(start), int(end) + 1):
                rnames.append('v' + str(rindex))

        return rnames

    def get_arguments_1(self, protos, rnames, registers):
         # 参数获取 "arguments": ["I:198", "I:115", "I:26"]}
        arguments = []
        ridx = -1
        for item in protos:
            ridx += 1
            key = 'p' + str(ridx)
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

    def get_cmr_names(self, line, results):
        mtd_groups = results.groups()
        cls_name = mtd_groups[-3][1:].replace('/', '.')
        mtd_name = mtd_groups[-2]

        # register_names
        rnames = []
        # invoke - static {v14, v16},
        if 'range' not in line:
            rnames.extend(mtd_groups[0].split(', '))
        elif 'range' in line:
            # invoke-static/range {v14 .. v16}
            tmp = re.match(r'v(\d+).*?(\d+)', mtd_groups[0])
            if not tmp:
                return
            start, end = tmp.groups()
            for rindex in range(int(start), int(end) + 1):
                rnames.append('v' + str(rindex))
        return cls_name, mtd_name, rnames

    def __process_slowly(self, protos, pattern):
        '''
        模板仅仅匹配解密方法的本身。
        如果方法体存在大量代码，可能需要执行大量的smali指令，相对比较慢。
        但是，相对精准匹配，比较通用。
        '''
        templet_prog = re.compile(pattern)

        move_result_obj_ptn = r'move-result-object ([vp]\d+)'
        move_result_obj_prog = re.compile(move_result_obj_ptn)

        argument_is_arr = 'arr' in self.tname

        arr_data_prog = re.compile(self.ARRAY_DATA_PATTERN)

        for sf in self.smalidir:
            for mtd in sf.get_methods():
                registers = {}

                # if 'e(JLjava/lang/Object;)I' not in str(mtd):
                #     continue

                # 如果存在数组
                array_data_content = []
                result = arr_data_prog.search(mtd.get_body())
                if result:
                    array_data_content = re.split(r'\n\s', result.group())

                lines = re.split(r'\n\s*', mtd.get_body())

                tmp_bodies = lines.copy()

                flag = False
                new_body = []
                snippet = []
                args = {}

                cls_name = None
                mtd_name = None
                old_content = None

                lidx = -1
                json_item = None
                for line in lines:

                    snippet.append(line)
                    lidx += 1

                    result_mtd = templet_prog.search(line)
                    if not result_mtd:
                        new_body.append(line)
                        continue

                    # print(line.encode())

                    if 'Ljava/lang/String;->valueOf(I)Ljava/lang/String;' in line:
                        new_body.append(line)
                        continue

                    if 'Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;' in line:
                        new_body.append(line)
                        continue

                    cls_name, mtd_name, rnames = self.get_cmr_names(
                        line, result_mtd)

                    # print(cls_name.encode('utf-8'),
                    #       mtd_name.encode('utf-8'), rnames)

                    # 初始化寄存器
                    del snippet[-1]
                    snippet.extend(array_data_content)
                    try:
                        args.update(self.pre_process(snippet))
                    except TIMEOUT_EXCEPTION:
                        pass
                    # for x in snippet:
                    #     print(x.encode('utf-8'))

                    try:
                        registers = self.get_registers(snippet, args, rnames)
                        args = registers if registers else args
                    except TIMEOUT_EXCEPTION as ex:
                        snippet.clear()
                        continue

                    # for k in registers:
                    #     print(k.encode(), args[k])

                    snippet.clear()

                    if not registers:
                        continue

                    # 参数获取 "arguments": ["I:198", "I:115", "I:26"]}
                    arguments = []
                    # args = {}  # the parameter of smali method
                    ridx = -1
                    for item in protos:
                        ridx += 1
                        key = 'p' + str(ridx)
                        rname = rnames[ridx]
                        if rname not in registers:
                            break
                        value = registers[rnames[ridx]]
                        argument = self.convert_args(item, value)
                        if argument is None:
                            break
                        arguments.append(argument)
                        # args[key] = argument.split(':')[1]

                    if len(arguments) != len(protos):
                        continue

                    # 解密方式1 - smaliemu 执行
                    # self.smali_call(cls_name, mtd_name, args)

                    json_item = self.get_json_item(cls_name, mtd_name,
                                                   arguments)
                    # print(json_item)

                    # make the line unique, # {id}_{rtn_name}
                    old_content = '# %s' % json_item['id']

                    # 解密方式2 - 推送手机执行
                    # If next line is move-result-object, get return
                    # register name.
                    # print(lines)
                    res = move_result_obj_prog.search(lines[lidx + 1])
                    if res:
                        rtn_name = res.groups()[0]
                        # To avoid '# abc_v10' be replace with '# abc_v1'
                        old_content = old_content + '_' + rtn_name + 'X'
                        self.append_json_item(json_item, mtd, old_content,
                                              rtn_name)
                    else:
                        old_content = old_content + '_X'
                        self.append_json_item(
                            json_item, mtd, old_content, None)

                    tmp_bodies[lidx] = old_content

                mtd.set_body('\n'.join(tmp_bodies))

            self.optimize()
            self.clear()

    @timeout(5)
    def get_registers(self, snippet, args, rnames):
        from smaliemu.emulator import Emulator
        emu2 = Emulator()
        emu2.call(snippet[-5:], args=args, thrown=False)

        result = self.varify_args(emu2.vm.variables, rnames)
        if result:
            return emu2.vm.variables

        emu2.call(snippet, args=args, thrown=False)
        result = self.varify_args(emu2.vm.variables, rnames)
        if result:
            return emu2.vm.variables

    def varify_args(self, args, rnames):
        for k in rnames:
            value = args.get(k, None)
            if value is None:
                return False
        return True

    @timeout(5)
    def smali_call(self, cls_name, mtd_name, args):
        '''执行解密方法

        {'v1': 86, 'v3': 47, 'v9': 20, 'v5': 67, 'v7': 82,
                     'v4': 9, 'v0': 1, 'v10': 0, 'v11': 56, 'v8': 20902}
        invoke - static {v3, v4, v5}, Lcom/a->a(III)Ljava/lang/String;
        '''

        from smaliemu.emulator import Emulator
        emu2 = Emulator()

        # print(cls_name, mtd_name)
        for sf in self.smali_files:
            # print(sf.class_name)
            # print(sf.class_sign)
            if cls_name in sf.class_name:
                # print(sf.methods)
                break
            # snippet = body.split('\n')
            # new_snippet = snippet.copy()
            # clz_sigs = set()
            # # has_arr = False
            # prog = re.compile(r'^.*, (.*?)->.*$')
            # for line in new_snippet:
            #     if 'sget' in line:
            #         clz_sigs.add(prog.match(line).groups()[0])
            #         if ':[' in line:
            #             has_arr = True

            # for clz_sig in clz_sigs:
            #     pass
            # mtds = self.smali_files_dict[clz_sig].methods_dict
            # if '<clinit>()V' in mtds:
            #     body = mtds['<clinit>()V'].body
            #     tmp = re.split(r'\n\s*', body)
            #     idx = tmp.index('return-void')
            #     start = tmp[:idx]
            #     end = tmp[idx + 1:]
            #     start.extend(snippet)
            #     start.extend(end)
            #     snippet = start.copy()

            # 初始化解密方法体
            # 获取方法体
            # 检测方法体，如果存在sget-object，则需要去对应的smalifile拷贝对应类的成员变量初始化方法内容
            # 合并方法体
            # ret = emu2.call(snippet, args,  thrown=False)
            # if ret:
            #     try:
            #         print(ret)
            #     except Exception:
            #         print(ret.encode('utf-8'))

            # else:
            #     print('Not result.')

            # 执行解密
            # 返回结果

    def convert_to_smali_parameter(self, arguments):
        pass

    @staticmethod
    def convert_args(typ8, value):
        '''Convert the value of register/argument to json format.'''
        if value is None:
            return None

        if typ8 == 'I':
            # print(value)
            if not isinstance(value, int):
                return None
            return 'I:' + str(value)

        if typ8 == 'B':
            # print(value)
            if not isinstance(value, int):
                return None
            return 'B:' + str(value)

        if typ8 == 'S':
            if not isinstance(value, int):
                return None
            return 'S:' + str(value)

        if typ8 == 'C':
            # don't convert to char, avoid some unreadable chars.
            return 'C:' + str(value)

        if typ8 == 'Ljava/lang/String;':
            if not isinstance(value, str):
                return None

            import codecs
            item = codecs.getdecoder('unicode_escape')(value)[0]
            args = []
            for i in item.encode("UTF-8"):
                args.append(i)
            return "java.lang.String:" + str(args)

        if typ8 == '[B':
            if not isinstance(value, list):
                return None
            byte_arr = []
            for item in value:
                if item == '':
                    item = 0
                byte_arr.append(item)
            return '[B:' + str(byte_arr)

        if typ8 == '[C':
            if not isinstance(value, list):
                return None
            byte_arr = []
            for item in value:
                if item == '':
                    item = 0
                byte_arr.append(item)
            return '[C:' + str(byte_arr)

        print('不支持该类型', typ8, value)
