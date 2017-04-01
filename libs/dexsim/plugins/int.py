# coding:utf-8

import sys
import hashlib
from json import JSONEncoder
import re

from libs.dexsim.plugin import Plugin

__all__ = ["INT"]


class INT(Plugin):

    name = "INT"
    version = '0.0.2'
    description = '解密参数是INT类型'

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self.__process_iii()
        self.__process_iii_plus()
        self.__process_i()
        self.__process_i()

    def __process_iii(self):
        '''
            const/16 v0, 0x21
            const/16 v2, -0x9
            const/4 v3, -0x1
            invoke-static {v0, v2, v3}, Lcom/android/system/admin/Br;->oIClIOIC(III)Ljava/lang/String;
            move-result-object v0

            ==>

            const-string v0, "android.content.Intent"
        '''

        INVOKE_STATIC_III = 'invoke-static \{[vp]\d+, [vp]\d+, [vp]\d+\}, L([^;]+);->([^\(]+\(III\))Ljava/lang/String;\s+'

        p = re.compile('\s+' + (self.CONST_NUMBER + '\s+') * 3 + INVOKE_STATIC_III + self.MOVE_RESULT_OBJECT)

        json_list = []
        target_contexts = {}
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                target = {}
                line = i.group()

                p2 = re.compile(self.CONST_NUMBER)
                args = []
                for j in p2.finditer(line):
                    cn = j.group().split(", ")
                    args.append('I:' + str(eval(cn[1])))

                p3 = re.compile(INVOKE_STATIC_III)
                cn_statement = p3.search(line).group()
                start = cn_statement.index('}, L')
                end = cn_statement.index(';->')
                classname = cn_statement[start + 4:end].replace('/', '.')

                args_index = cn_statement.index('(III)')
                methodname = cn_statement[end + 3:args_index]

                target = {'className': classname, 'methodName': methodname, 'arguments': args, }

                # 转换为[{'className':'', 'methodName':'', 'arguments':'', 'id':''}]
                ID = hashlib.sha256(JSONEncoder().encode(target).encode('utf-8')).hexdigest()
                target['id'] = ID

                p3 = re.compile(self.MOVE_RESULT_OBJECT)
                mro_statement = p3.search(line).group()
                return_variable_name = mro_statement[mro_statement.rindex(' ') + 1:]

                if ID not in target_contexts.keys():
                    target_contexts[ID] = [(mtd, line, '\n\n    const-string %s, ' % return_variable_name)]
                else:
                    target_contexts[ID].append((mtd, line, '\n\n    const-string %s, ' % return_variable_name))

                if target not in json_list:
                    json_list.append(target)

        self.optimizations(json_list, target_contexts)

    def __process_iii_plus(self):
        '''
            const/16 v0, 0x21
            ...
            const/16 v2, -0x9

            ...
            const/4 v3, -0x1

            invoke-static {v0, v2, v3}, Lcom/android/system/admin/Br;->oIClIOIC(III)Ljava/lang/String;
            move-result-object v0

            ==>

            const-string v0, "android.content.Intent"
        '''

        INVOKE_STATIC_III = 'invoke-static \{[vp]\d+, [vp]\d+, [vp]\d+\}, L([^;]+);->([^\(]+\(III\))Ljava/lang/String;\s+'

        p = re.compile(INVOKE_STATIC_III + self.MOVE_RESULT_OBJECT)

        json_list = []
        target_contexts = {}
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                target = {}
                line = i.group()

                tmps = line.split()

                argnames = []
                argnames.append(tmps[1][1:-1])
                argnames.append(tmps[2][:-1])
                argnames.append(tmps[3][:-2])
                # print(argnames)

                index = mtd.body.index(line)
                arrs = mtd.body[:index].split('\n')
                arrs.reverse()

                args = []
                for name in argnames:
                    reg = 'const(?:\/\d+) %s, (-?0x[a-f\d]+)' % name
                    p2 = re.compile(reg)
                    # print(reg)
                    for item in arrs:
                        match = p2.search(item)
                        if match:
                            match.group().split()[2]
                            args.append('I:' + str(eval(match.group().split()[2])))
                            break
                        elif name in item:
                            break

                # print(args)

                if len(args) < 3:
                    continue

                end = tmps[4].index(';->')
                classname = tmps[4][1:end].replace('/', '.')
                # print(classname)

                args_index = tmps[4].index('(III)')
                methodname = tmps[4][end + 3:args_index]
                # print(methodname)

                target = {'className': classname, 'methodName': methodname, 'arguments': args, }
                ID = hashlib.sha256(JSONEncoder().encode(target).encode('utf-8')).hexdigest()
                target['id'] = ID

                return_variable_name = tmps[-1]

                if ID not in target_contexts.keys():
                    target_contexts[ID] = [(mtd, line, '\n\n    const-string %s, ' % return_variable_name)]
                else:
                    target_contexts[ID].append((mtd, line, '\n\n    const-string %s, ' % return_variable_name))

                if target not in json_list:
                    json_list.append(target)

                # print(target)

        self.optimizations(json_list, target_contexts)

    def __process_ii(self):
        '''
            const/16 v2, -0x9
            const/4 v3, -0x1
            invoke-static {v0, .. v3}, Lcom/android/system/admin/Br;->oIClIOIC(II)Ljava/lang/String;
            move-result-object v0

            ==>

            const-string v0, "android.content.Intent"
        '''

        INVOKE_STATIC_II = r'invoke-static[/\s\w]+\{[vp,\d\s\.]+},\s+L([^;]+);->([^\(]+\(II\))Ljava/lang/String;\s+'

        p = re.compile('\s+' + (self.CONST_NUMBER + '\s+') * 2 + INVOKE_STATIC_II + self.MOVE_RESULT_OBJECT)

        json_list = []
        target_contexts = {}
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                target = {}
                line = i.group()

                p2 = re.compile(self.CONST_NUMBER)
                args = []
                for j in p2.finditer(line):
                    cn = j.group().split(", ")
                    args.append('I:' + str(eval(cn[1])))

                p3 = re.compile(INVOKE_STATIC_III)
                cn_statement = p3.search(line).group()
                start = cn_statement.index('}, L')
                end = cn_statement.index(';->')
                classname = cn_statement[start + 4:end].replace('/', '.')

                args_index = cn_statement.index('(III)')
                methodname = cn_statement[end + 3:args_index]

                target = {'className': classname, 'methodName': methodname, 'arguments': args, }

                # 转换为[{'className':'', 'methodName':'', 'arguments':'', 'id':''}]
                ID = hashlib.sha256(JSONEncoder().encode(target).encode('utf-8')).hexdigest()
                target['id'] = ID

                p3 = re.compile(self.MOVE_RESULT_OBJECT)
                mro_statement = p3.search(line).group()
                return_variable_name = mro_statement[mro_statement.rindex(' ') + 1:]

                if ID not in target_contexts.keys():
                    target_contexts[ID] = [(mtd, line, '\n\n    const-string %s, ' % return_variable_name)]
                else:
                    target_contexts[ID].append((mtd, line, '\n\n    const-string %s, ' % return_variable_name))

                if target not in json_list:
                    json_list.append(target)

        self.optimizations(json_list, target_contexts)

    def __process_i(self):
        '''
            const/16 v1, 0x22

            invoke-static {v1}, Lcom/zbfygv/rwpub/StringTable;->get(I)Ljava/lang/String;

            move-result-object v1

            ==>

            const-string v0, "android.content.Intent"
        '''

        #print('__process_i')

        INVOKE_STATIC_III = r'invoke-static[/\s\w]+\{[vp,\d\s\.]+},\s+L([^;]+);->([^\(]+\(I\))Ljava/lang/String;\s+'

        p = re.compile('\s+' + self.CONST_NUMBER + '\s+' + INVOKE_STATIC_III + self.MOVE_RESULT_OBJECT)

        json_list = []
        target_contexts = {}
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                target = {}
                line = i.group()

                p2 = re.compile(self.CONST_NUMBER)
                args = []
                for j in p2.finditer(line):
                    cn = j.group().split(", ")
                    args.append('I:' + str(eval(cn[1])))

                #print(args)

                p3 = re.compile(INVOKE_STATIC_III)
                cn_statement = p3.search(line).group()
                start = cn_statement.index('}, L')
                end = cn_statement.index(';->')
                classname = cn_statement[start + 4:end].replace('/', '.')

                args_index = cn_statement.index('(I)')
                methodname = cn_statement[end + 3:args_index]

                target = {'className': classname, 'methodName': methodname, 'arguments': args, }

                # 转换为[{'className':'', 'methodName':'', 'arguments':'', 'id':''}]
                ID = hashlib.sha256(JSONEncoder().encode(target).encode('utf-8')).hexdigest()
                target['id'] = ID

                p3 = re.compile(self.MOVE_RESULT_OBJECT)
                mro_statement = p3.search(line).group()
                return_variable_name = mro_statement[mro_statement.rindex(' ') + 1:]

                if ID not in target_contexts.keys():
                    target_contexts[ID] = [(mtd, line, '\n\n    const-string %s, ' % return_variable_name)]
                else:
                    target_contexts[ID].append((mtd, line, '\n\n    const-string %s, ' % return_variable_name))

                if target not in json_list:
                    json_list.append(target)

        self.optimizations(json_list, target_contexts)
