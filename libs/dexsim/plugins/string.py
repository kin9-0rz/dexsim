# coding:utf-8

import sys
import hashlib
from json import JSONEncoder
import re

from libs.dexsim.plugin import Plugin


__all__ = ["STRING"]


class STRING(Plugin):

    name = "STRING"
    version = '0.0.2'
    # make_changes = False

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self.__process_one_argument()

    def __process_one_argument(self):

        '''

            const-string v3, "F7095AB6386E1D0567FBB5D11AF2268ADC7FB9C7F82756AA"

            invoke-static {v3}, Lcom/android/google/mfee/GoogleEncryption;->decryptData2(Ljava/lang/String;)Ljava/lang/String;

            move-result-object v3

            ==>

            const-string v3, "------decode result-------"

        '''

        INVOKE_STATIC = 'invoke-static \{[vp]\d+}, L([^;]+);->([^\(]+\(Ljava/lang/String;\))Ljava/lang/String;\s+'

        p = re.compile('\s+' + self.CONST_STRING + '\s+' + INVOKE_STATIC + self.MOVE_RESULT_OBJECT)

        json_list = []
        target_contexts = {}
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                test = {}
                line = i.group()

                # get arguments
                args = []
                start = line.index('"')
                end = line.rindex('"')
                s = line[start + 1:end]

                arg1 = []
                for item in s.encode("UTF-8"):
                    arg1.append(item)
                args.append("java.lang.String:" + str(arg1))

                # get classname
                start = line.index('}, L')
                end = line.index(';->')
                classname = line[start + 4:end].replace('/', '.')

                # get method name
                args_index = line.index('(Ljava/lang/String;)')
                methodname = line[end + 3:args_index]

                test = {'className': classname, 'methodName': methodname, 'arguments': args, }

                # [{'className':'', 'methodName':'', 'arguments':'', 'id':''}]
                id = hashlib.sha256(JSONEncoder().encode(test).encode('utf-8')).hexdigest()
                test['id'] = id

                # get return variable name
                p3 = re.compile(self.MOVE_RESULT_OBJECT)
                mro_statement = p3.search(line).group()
                return_variable_name = mro_statement[mro_statement.rindex(' ') + 1:]

                if id not in target_contexts.keys():
                    target_contexts[id] = [(mtd, line, '\n\n    const-string %s, ' % return_variable_name)]
                else:
                    target_contexts[id].append((mtd, line, '\n\n    const-string %s, ' % return_variable_name))

                # print(test)
                if test not in json_list:
                    json_list.append(test)

        self.optimizations(json_list, target_contexts)
