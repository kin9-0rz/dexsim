# coding:utf-8

import sys
import hashlib
from json import JSONEncoder
import re

from libs.dexsim.plugin import Plugin

__all__ = ["INT"]


class INT(Plugin):

    name = "INT"
    version = '0.0.3'
    description = '解密参数是INT类型'
    enabled = False

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self.__process_iii_1()
        self.__process_iii_2()
        self.__process_ii()
        self.__process_i()

    def __process_iii_1(self):
        '''
            const/16 v0, 0x21
            const/16 v2, -0x9
            const/4 v3, -0x1
            invoke-static {v0, v2, v3}, La/b/c;->func(III)Ljava/lang/String;
            move-result-object v0

            ==>

            const-string v0, "decode string"
        '''
        invoke_ptn = self.get_invoke_pattern('III')
        target_ptn = '\s+' + (self.CONST_NUMBER + '\s+') * 3 + invoke_ptn + self.MOVE_RESULT_OBJECT
        print(target_ptn)

        prog = re.compile(target_ptn)

        self.json_list = []
        self.target_contexts = {}

        for mtd in self.methods:
            for i in prog.finditer(mtd.body):
                line = i.group()

                cls_name, mtd_name, rtn_name = self.get_clz_mtd_rtn_name(line)
                args = self.get_arguments(None, line, 'I')
                if len(args) != 3:
                    continue

                json_item = self.get_json_item(cls_name, mtd_name, args)

                self.append_json_item(json_item, mtd, line, rtn_name)


        self.optimize()

    def __process_iii_2(self):
        '''
            有时候，参数定义的时候，顺序不一致，或者之间存在其他干扰。

            const/16 v0, 0x21
            ...
            const/16 v2, -0x9

            ...
            const/4 v3, -0x1

            invoke-static {v0, v2, v3}, La/b/c;->func(III)Ljava/lang/String;
            move-result-object v0

            ==>

            const-string v0, "Decode String"
        '''
        invoke_ptn = self.get_invoke_pattern('III')
        prog = re.compile(invoke_ptn + self.MOVE_RESULT_OBJECT)
        print(invoke_ptn + self.MOVE_RESULT_OBJECT)
        self.json_list = []
        self.target_contexts = {}

        for mtd in self.methods:
            for i in prog.finditer(mtd.body):
                target = {}
                line = i.group()

                tmps = line.split()

                argnames = []
                argnames.append(tmps[1][1:-1])
                argnames.append(tmps[2][:-1])
                argnames.append(tmps[3][:-2])

                index = mtd.body.index(line)
                arrs = mtd.body[:index].split('\n')
                arrs.reverse()

                args = []
                for name in argnames:
                    reg = 'const(?:\/\d+) %s, (-?0x[a-f\d]+)' % name
                    p2 = re.compile(reg)
                    for item in arrs:
                        match = p2.search(item)
                        if match:
                            match.group().split()[2]
                            args.append('I:' + str(eval(match.group().split()[2])))
                            break
                        elif name in item:
                            break

                if len(args) < 3:
                    continue

                cls_name, mtd_name, rtn_name = self.get_clz_mtd_rtn_name(line)

                json_item = self.get_json_item(cls_name, mtd_name, args)

                self.append_json_item(json_item, mtd, line, rtn_name)

        self.optimize()

    def __process_ii(self):
        '''
            const/16 v2, -0x9
            const/4 v3, -0x1
            invoke-static {v2, .. v3}, La/b/c;->func(II)Ljava/lang/String;
            move-result-object v0

            ==>

            const-string v0, "Decode String"
        '''

        INVOKE_STATIC_II = self.get_invoke_pattern('II')
        prog = re.compile('\s+' + self.CONST_NUMBER * 2 + INVOKE_STATIC_II + self.MOVE_RESULT_OBJECT)
        print('\s+' + self.CONST_NUMBER * 2 + INVOKE_STATIC_II + self.MOVE_RESULT_OBJECT)
        self.json_list = []
        self.target_contexts = {}

        for mtd in self.methods:
            for i in prog.finditer(mtd.body):
                line = i.group()

                args = self.get_arguments(None, line, 'I')
                if len(args) != 2:
                    continue

                cls_name, mtd_name, rtn_name = self.get_clz_mtd_rtn_name(line)

                json_item = self.get_json_item(cls_name, mtd_name, args)
                self.append_json_item(json_item, mtd, line, rtn_name)

        self.optimize()

    def __process_i(self):
        '''
            const/16 v1, 0x22

            invoke-static {v1}, Lcom/zbfygv/rwpub/StringTable;->get(I)Ljava/lang/String;

            move-result-object v1

            ==>

            const-string v0, "android.content.Intent"
        '''
        INVOKE_STATIC_I = self.get_invoke_pattern('I')
        prog = re.compile('\s+' + self.CONST_NUMBER + INVOKE_STATIC_I + self.MOVE_RESULT_OBJECT)
        print('\s+' + self.CONST_NUMBER + INVOKE_STATIC_I + self.MOVE_RESULT_OBJECT)
        json_list = []
        target_contexts = {}
        for mtd in self.methods:
            for i in prog.finditer(mtd.body):
                line = i.group()

                args = self.get_arguments(None, line, 'I')
                if not args:
                    continue

                cls_name, mtd_name, rtn_name = self.get_clz_mtd_rtn_name(line)
                json_item = self.get_json_item(cls_name, mtd_name, args)
                self.append_json_item(json_item, mtd, line, rtn_name)

        self.optimize()
