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

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self.__load_templets()

    def __load_templets(self):
        print()
        templets_path = os.path.dirname(__file__)[:-7] + 'templets'
        for filename in os.listdir(templets_path):
            file_path = os.path.join(templets_path, filename)
            with open(file_path, encoding='utf-8') as f:
                datas = yaml.load(f.read())
                for item in datas:
                    for key, value in item.items():
                        self.tname = key

                        if not value['enabled']:
                            print('Not Load templet:', self.tname)
                            continue
                        print('Load templet:', self.tname)
                        if value['protos']:
                            protos = [i.replace('\\', '')
                                      for i in value['protos']]
                        else:
                            protos = []
                        ptn = ''.join(value['pattern'])
                        self.__process(protos, ptn)

    def __process(self, protos, pattern):
        templet_prog = re.compile(pattern)

        move_result_obj_ptn = r'move-result-object ([vp]\d+)'
        move_result_obj_prog = re.compile(move_result_obj_ptn)

        argument_is_arr = 'arr' in self.tname

        for sf in self.smalidir:
            for mtd in sf.get_methods():
                registers = {}
                array_datas = {}

                if 'q;->run()' not in str(mtd):
                    continue

                print(str(mtd))

                result = templet_prog.search(mtd.get_body())
                if not result:
                    continue

                if argument_is_arr:
                    array_datas = self.init_array_datas(mtd.get_body())
                    if not array_datas:
                        continue

                lines = re.split(r'\n', mtd.get_body())

                tmp_bodies = lines.copy()

                cls_name = None
                mtd_name = None
                old_content = None

                lidx = -1
                json_item = None
                for line in lines:
                    print(line)
                    lidx += 1
                    result_mtd = templet_prog.search(line)
                    if not result_mtd:
                        continue

                    if 'Ljava/lang/String;->valueOf(I)Ljava/lang/String;' in line:
                        continue

                    if 'Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;' in line:
                        continue

                    mtd_groups = result_mtd.groups()
                    cls_name = mtd_groups[-3][1:].replace('/', '.')
                    mtd_name = mtd_groups[-2]
                    # print(mtd_groups)

                    # 参数处理

                    register_names = []
                    # invoke - static {v14, v16},
                    if 'range' not in line:
                        register_names.extend(mtd_groups[0].split(', '))
                    elif 'range' in line:
                        # invoke-static/range {v14 .. v16}
                        tmp = re.match(r'v(\d+).*?(\d+)', mtd_groups[0])
                        if not tmp:
                            continue
                        start, end = tmp.groups()
                        for rindex in range(int(start), int(end) + 1):
                            register_names.append('v' + str(rindex))

                    # self.get_register_names(line)

                    try:
                        tmpx = lines[:lidx]
                        print('*' * 100)
                        print(tmpx[-1])
                        print('*' * 100)
                        exit()
                        registers = self.get_registers(lines[:lidx])
                    except TIMEOUT_EXCEPTION as ex:
                        print(ex)
                        print('超时，优化或者使用其他方式获取')
                        continue

                    print(registers)

                    # 参数获取 "arguments": ["I:198", "I:115", "I:26"]}
                    arguments = []
                    args = {}  # the parameter of smali method
                    ridx = -1
                    for item in protos:
                        ridx += 1
                        key = 'p' + str(ridx)
                        rname = register_names[ridx]
                        if rname not in registers:
                            break
                        value = registers[register_names[ridx]]
                        argument = self.convert_args(item, value)
                        if argument is None:
                            break
                        arguments.append(argument)
                        args[key] = argument.split(':')[1]

                    if len(arguments) != len(protos):
                        continue

                    # 解密处理

                    # 尝试直接调用smali方法解密
                    # 如果成功，则体会
                    # 失败则考虑反射调用
                    # self.smali_call(cls_name, mtd_name, args)

                    json_item = self.get_json_item(cls_name, mtd_name,
                                                   arguments)
                    print(json_item)

                    # make the line unique, # {id}_{rtn_name}
                    old_content = '# %s' % json_item['id']

                    # If next line is move-result-object, get return
                    # register name.
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

    def get_register_names(self, line):
        '''invoke-static
        '''
        print(line)
        names = re.search(r'{(.*?)}', line).groups()[0]
        if 'range' not in line:
            # invoke - static {v14, v16},
            return names.split(', ')
        elif 'range' in line:
            # invoke-static/range {v14 .. v16}
            print(names)
            # tmp = re.match(r'v(\d+).*?(\d+)', mtd_groups[0])
            # if not tmp:
            #     continue
            # start, end = tmp.groups()
            # for rindex in range(int(start), int(end) + 1):
            #     register_names.append('v' + str(rindex))

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

    def convert_to_smali_parameter(arguments):
        pass

    @timeout(5)
    def get_registers(self, lines):
        from smaliemu.emulator import Emulator
        emu2 = Emulator()
        snippet = lines.copy()
        print('\n'.join(snippet))

        exit()
        raise Exception

        snippet = self.merge_body(lines)

        for line in snippet.copy():
            if 'iget-boolean' in line:
                snippet.remove(line)
            elif 'const-class' in line:
                snippet.remove(line)
            elif line.startswith('if-'):
                snippet.remove(line)
            elif line.startswith('return-'):
                snippet.remove(line)
            elif line.startswith(':try_end'):
                snippet.remove(line)
            elif line.startswith('goto'):
                snippet.remove(line)

        # FIXME 存在执行时间过长的问题
        print('\n'.join(snippet))
        emu2.call(snippet, thrown=False)

        return emu2.vm.variables

    def merge_body(self, snippet):
        clz_sigs = set()
        prog = re.compile(r'^.*, (.*?)->.*$')
        for line in snippet:
            if 'sget' in line:
                clz_sigs.add(prog.match(line).groups()[0])

        for clz_sig in clz_sigs:
            for sf in self.smali_files:
                if clz_sig != sf.sign:
                    continue

                for mtd in sf.methods:
                    mtd_sign = mtd.signature
                    if '<clinit>()V' in mtd_sign:
                        body = mtd.get_body()
                        tmp = re.split(r'\n\s*', body)
                        idx = tmp.index('return-void')
                        start = tmp[:idx]
                        end = tmp[idx + 1:]
                        start.extend(snippet)
                        start.extend(end)
                        snippet = start.copy()
                    elif '<init>()V' in mtd_sign:
                        body = mtd.get_body()
                        tmp = re.split(r'\n\s*', body)
                        idx = tmp.index('return-void')
                        start = tmp[:idx]
                        end = tmp[idx + 1:]
                        start.extend(snippet)
                        start.extend(end)
                        snippet = start.copy()

        return snippet

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

    def init_array_datas(self, body):
        array_datas = {}

        ptn2 = r'(:array_[\w\d]+)\s*.array-data[\w\W\s]+?.end array-data'
        arr_data_prog = re.compile(ptn2)

        for item in arr_data_prog.finditer(body):
            array_data_content = re.split(r'\n\s*', item.group())
            line = 'fill-array-data v0, %s' % item.groups()[0]
            snippet = []
            snippet.append(line)
            snippet.append('return-object v0')
            snippet.extend(array_data_content)
            arr_data = self.emu.call(snippet)
            array_datas[item.groups()[0]] = arr_data

        return array_datas
