# coding:utf-8

import hashlib
from json import JSONEncoder
import re

from libs.dexsim.plugin import Plugin


__all__ = ["STRING"]


class STRING(Plugin):

    name = "STRING"
    version = '0.0.3'
    enabled = False

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self.__process_3_argument()
        self.__process_2_argument()
        self.__process_1_argument()

    def __process_1_argument(self):

        '''
            const-string v3, "encode string"

            invoke-static {v3}, La/b/c;->decryptData2(Ljava/lang/String;)Ljava/lang/String;

            move-result-object v3

            ==>

            const-string v3, "decode string"

            其他字符串的情况，可能匹配不上：
            const-string v1, "&\u0008%\u000c"
            invoke-static {v1}, Lkris/myapplication/c;->a(Ljava/lang/String;)Ljava/lang/String;
            move-result-object v1

        '''

        INVOKE_STATIC = self.get_invoke_pattern('Ljava/lang/String;')

        p = re.compile('\s+' + self.CONST_STRING + '\s+' + INVOKE_STATIC + self.MOVE_RESULT_OBJECT)

        print('\s+' + self.CONST_STRING + '\s+' + INVOKE_STATIC + self.MOVE_RESULT_OBJECT)

        self.json_list = []
        self.target_contexts = {}
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                line = i.group()

                args = self.get_arguments(None, line, 'java.lang.String')
                if not args:
                    continue

                cls_name, mtd_name, rtn_name = self.get_clz_mtd_rtn_name(line)

                json_item = self.get_json_item(cls_name, mtd_name, args)
                self.append_json_item(json_item, mtd, line, rtn_name)

        self.optimize()

    def __process_2_argument(self):
        INVOKE_STATIC = self.get_invoke_pattern('Ljava/lang/String;Ljava/lang/String;')

        prog = re.compile(self.CONST_STRING * 2 + INVOKE_STATIC + self.MOVE_RESULT_OBJECT)

        self.json_list = []
        self.target_contexts = {}
        for mtd in self.methods:
            for i in prog.finditer(mtd.body):
                line = i.group()

                # get arguments
                # TODO 应该有更好的办法，直接提取所有的字符串。
                args = []
                prog2 = re.compile(CONST_STRING)
                for j in prog2.finditer(line):
                    const_str = re.findall("\w+",j.group())[-1]
                    arg = []
                    for item in const_str.encode("UTF-8"):
                        arg.append(item)
                    args.append("java.lang.String:" + str(arg))

                if not args:
                    continue

                cls_name, mtd_name, rtn_name = self.get_clz_mtd_rtn_name(line)
                json_item = self.get_json_item(cls_name, mtd_name, args)
                self.append_json_item(json_item, mtd, line, rtn_name)

        self.optimize()

    def __process_3_argument(self):
        '''
            const-string v0, "4db8c06f8baa2fa97518e2fbc78aed7a"

            const-string v1, "dcc6ee73b95b7008865a1241a3f9f2d4"

            const-string v2, "89cf037654ae21bd"

            invoke-static {v0, v1, v2}, Lnpnojrqk/niwjucst/oifhebjg/uihmjzfs/agntdkrh/xumvnbpc/jqwutfvs/dfkxcwot/hcsplder;->alxrefmv(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

            move-result-object v0

            ==>

            const-string v0, "------decode result-------"

            ---------------------------------------------------------

            const-string v29, "b3547fe0b848a8c73e30d89c473cd167"

            const-string v30, "07e942bf3a4751a9c188cf652d6dbe03"

            const-string v31, "b1a840dfc932e576"

            invoke-static/range {v29 .. v31}, Lnpnojrqk/niwjucst/oifhebjg/uihmjzfs/agntdkrh/xumvnbpc/jqwutfvs/dfkxcwot/hcsplder;->alxrefmv(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

            move-result-object v29

            -------------------------

            const-string v7, "20bb21a548d01d8ff9cbebd1fc53d5ec"

            const-string v8, "a342bbcc85268df9e4a7f9e1307d6015"

            const-string v9, "6c7a9f8014ed32b5"

            invoke-static {v7, v8, v9}, Lnpnojrqk/niwjucst/oifhebjg/uihmjzfs/agntdkrh/xumvnbpc/jqwutfvs/dfkxcwot/hcsplder;->alxrefmv(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
            :try_end_69
            .catch Ljava/lang/Exception; {:try_start_60 .. :try_end_69} :catch_59

            move-result-object v3

        '''
        ESCAPE_STRING = '''"(.*?)"'''
        CONST_STRING = 'const-string [vp]\d+, ' + ESCAPE_STRING + '.*\s+'
        INVOKE_STATIC = 'invoke-static[/\s\w]+\{[vp,\d\s\.]+},\s+L([^;]+);->([^\(]+\(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;\))Ljava/lang/String;\s+'

        p = re.compile('\s+' + CONST_STRING + CONST_STRING + CONST_STRING + INVOKE_STATIC + self.MOVE_RESULT_OBJECT)

        json_list = []
        target_contexts = {}
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                test = {}
                line = i.group()

                # TODO 后续再考虑使用通用的方式获取参数
                # get arguments
                args = []
                match_string = re.compile(CONST_STRING)
                for j in match_string.finditer(line):
                    const_str = re.findall("\w+",j.group())[-1]
                    arg = []
                    for item in const_str.encode("UTF-8"):
                        arg.append(item)
                    args.append("java.lang.String:" + str(arg))

                # get classname
                start = line.index('}, L')
                end = line.index(';->')
                classname = line[start + 4:end].replace('/', '.')

                # get method name
                args_index = line.index('(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)')
                methodname = line[end + 3:args_index]

                test = {'className': classname, 'methodName': methodname, 'arguments': args, }

                # [{'className':'', 'methodName':'', 'arguments':'', 'id':''}]
                ID = hashlib.sha256(JSONEncoder().encode(test).encode('utf-8')).hexdigest()
                test['id'] = ID

                # get return variable name
                p3 = re.compile(self.MOVE_RESULT_OBJECT)
                mro_statement = p3.search(line).group()
                rtn_name = mro_statement[mro_statement.rindex(' ') + 1:]

                if ID not in target_contexts.keys():
                    target_contexts[ID] = [(mtd, line, '\n\n    const-string %s, ' % rtn_name)]
                else:
                    target_contexts[ID].append((mtd, line, '\n\n    const-string %s, ' % rtn_name))

                if test not in json_list:
                    json_list.append(test)

        self.optimizations(json_list, target_contexts)
