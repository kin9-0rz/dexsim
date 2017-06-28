# coding:utf-8

import hashlib
from json import JSONEncoder
import re
import os
import yaml

from libs.dexsim.plugin import Plugin


__all__ = ["TEMPLET"]


class TEMPLET(Plugin):

    name = "TEMPLET"
    version = '0.0.1'
    enabled = True

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self.__load_templets()

    def __load_templets(self):
        templets_path = os.path.dirname(__file__)[:-7] + 'templets'
        for filename in os.listdir(templets_path):
            with open(templets_path + os.sep + filename) as f:
                datas = yaml.load(f.read())
                for item in datas:
                    for key in item:
                        if not item[key]['enabled']:
                            continue
                        args = item[key]['args'].replace('\\', '')
                        reg = ''.join(item[key]['reg'])
                        self.__process(args, reg)

    def __process(self, args, reg):
        p = re.compile(reg)

        self.json_list = []
        self.target_contexts = {}
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                line = i.group()
                # FIXME 参数的检索方法
                # 有可能存在参数与调用函数之间，有其他代码，这样就无法匹配到了
                # 如果把参数和调用方法，分开匹配
                # 那么则会增加替换的难度
                #
                # 如果一定要用：
                # 定位的方法，采用行数定位的方法。
                # 1. 先匹配方法，得到所在的行
                # 2. 从当前行回溯，找参数
                # 3. 找到则获取参数，找不到，则继续匹配下一个函数
                #
                # 替换的时候
                # 如果解密成功，则直接删掉参数所在的行 —— 可以考虑保留
                # 直接替换调用函数所在的行
                arguments = self.get_arguments(mtd.body, line, args)
                if not arguments:
                    continue

                cls_name, mtd_name, rtn_name = self.get_clz_mtd_rtn_name(line)
                json_item = self.get_json_item(cls_name, mtd_name, arguments)
                self.append_json_item(json_item, mtd, line, rtn_name)

        self.optimize()

    def __proces11s():
        INVOKE_STATIC = r'invoke-static[/\s\w]+\{([vp,\d\s\.]+)},\s+([^;]+);->(.*?)\((.*?)\)(.*)\s*'
        CONST_STRING = 'const-string (v\d+), "(.*?)".*'

        contst_str_re = re.compile(CONST_STRING)
        invoke_static_re = re.compile(INVOKE_STATIC)
        move_result_object_re = re.compile(self.MOVE_RESULT_OBJECT)

        # move-object/from16      v0, v18
        move_object_from_re = re.compile(r'move-object/from\d+\s+(.*?),\s+(.*)')

        self.json_list = []
        self.target_contexts = {}

        line_re = re.compile(r'\.line \d+([.\w\s,-{}\(\)]*)')

        CONST_NUMBER = r'const\/\d+\s+([vp]\d+), (-?0x[a-f\d]+)\s+'
        contst_num_re = re.compile(CONST_NUMBER)

        support_types = {'B', 'I', 'C', 'J', 'D', 'F', 'Ljava/lang/String;'}
        for mtd in self.methods:
            registers = {}

            args = []
            cls_name = None
            mtd_name = None
            rtn_name = None

            for line in re.split(r'.line \d+', mtd.body):
                # 解析出现的参数
                # 字符串参数
                # 如果不清楚，先不转换？
                csr = contst_str_re.search(line)
                if csr:
                    registers[csr.groups()[0]] = csr.groups()[1]
                    # print(line)
                    # arg = []
                    # for item in csr.groups()[1].encode("UTF-8"):
                    #     arg.append(item)
                    # registers[csr.groups()[0]] = "java.lang.String:" + str(arg)
                # 参数 - 数值
                cnr = contst_num_re.search(line)
                if cnr:
                    # print(line)
                    # print(cnr.groups())
                    # registers[cnr.groups()[0]] = "X:" + str(arg)
                    registers[cnr.groups()[0]] = cnr.groups()[1]

                # 赋值
                results = move_object_from_re.findall(line)
                for x, y in results:
                    try:
                        registers[x] = registers[y]
                    except KeyError:
                        if x in registers:
                            registers.pop(x)
                        continue

                # 解密方法调用
                isr = invoke_static_re.search(line)
                if isr:
                    # print('-' * 100)
                    # print(line)
                    # print(isr.groups())
                    flag = False
                    types = self.get_types(isr.groups()[3])
                    for item in types:
                        # if item != 'Ljava/lang/String;':
                        if item not in support_types:
                            flag = True
                            break
                    if flag:
                        continue
                    args_num = len(types)

                    args = []
                    regs_name = re.sub('\.|,', '', isr.groups()[0]).split()

                    if args_num == 1 != len(regs_name):
                        try:
                            arg = self.convert_type(types[0], registers[regs_name[1]])
                            if arg:
                                args.append(arg)
                        except KeyError:
                            continue
                    else:
                        i = 0
                        for key in regs_name:
                            try:
                                arg = self.convert_type(types[i], registers[key])
                                if arg:
                                    args.append(arg)
                                i += 1
                            except KeyError:
                                args = []

                    cls_name = isr.groups()[1][1:].replace('/', '.')
                    mtd_name = isr.groups()[2]

                if cls_name:
                    mror = move_result_object_re.search(line)
                    if mror:
                        rtn_name = mror.groups()[0]

                        print(cls_name, mtd_name, args)

                        json_item = self.get_json_item(cls_name, mtd_name, args)
                        self.append_json_item2(json_item, mtd, line, rtn_name)

                        args = []
                        cls_name = None
                        mtd_name = None
                        continue

        self.optimize2()
