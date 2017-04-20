import re
import sys
import hashlib
from json import JSONEncoder
import tempfile
import os

from libs.dexsim.plugin import Plugin


__all__ = ["NEW_STRING"]


class NEW_STRING(Plugin):

    name = "NEW_STRING"
    version = '0.0.2'

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self.__process_new_string()
        # self.__process_new_string_2()

    def __process_new_string(self):
        '''
            new String(byte[]{})

            ---

            # define new array
            const/16 v1, 0x14
            new-array v1, v1, [B
            fill-array-data v1, :array_4e

            new-instance v2, Ljava/lang/String;

            new-instance v3, Ljava/lang/String;

            invoke-direct {v3, v1}, Ljava/lang/String;-><init>([B)V

            ...
            # array data
            :array_4e
            .array-data 1
                0x4ct
                0x33t
                ...
            .end array-data

            ==>

            new-instance v2, Ljava/lang/String;

            const-string v3, "decode string"

        '''
        NEW_ARRAY = 'new-array [vp]\d+, [vp]\d+, \[B'
        FILL_ARRAY_DATA = 'fill-array-data [vp]\d+, :array_[\w\d]+'
        NEW_INSTANCE = 'new-instance [vp]\d+, Ljava\/lang\/String;'
        STRING_INIT = 'invoke-direct {[vp]\d+, [vp]\d+}, Ljava\/lang\/String;-><init>\(\[B\)V'

        p1 = re.compile('\s+' + self.CONST_NUMBER + '\s+' + NEW_ARRAY + '\s+' +
                        FILL_ARRAY_DATA + '\s+((' + NEW_INSTANCE + ')\s+)*' +
                        STRING_INIT)

        for mtd in self.methods:
            for i in p1.finditer(mtd.body):
                line = i.group()

                p2 = re.compile(':array_[\w\d]+')
                array_data_name = p2.search(line).group()

                reg = '\s+' + array_data_name + '\s+.array-data 1\s+' + '((0x[\da-f]{2}t)\s+)+' + '.end array-data'
                p2 = re.compile('\s+' + array_data_name + '\s+.array-data 1\s+' + '[\w\s]+' + '.end array-data')

                array_data_context = p2.search(mtd.body).group()

                # get return varialbe name
                p3 = re.compile(STRING_INIT)
                string_init_statement = p3.search(line).group()
                start = string_init_statement.index('{')
                end = string_init_statement.index(',')
                return_variable_name = string_init_statement[start + 1:end]

                # get string value
                newstr = ''
                for item in array_data_context.split()[3:-2]:
                    newstr = newstr + (chr(eval(item[:-1])))

                const_string_statement = 'const-string ' + return_variable_name + ', ' + '"' + newstr + '"'

                index = line.index(array_data_name)

                new_context = line[index + len(array_data_name):].replace(string_init_statement, const_string_statement)

                mtd.body = mtd.body.replace(line, new_context).replace(array_data_context, '')
                mtd.modified = True
                self.make_changes = True

        self.smali_files_update()


    # FIXME 插件失效，待处理
    def __process_new_string_2(self):

        '''

            new String(decode2bytes('encoding string'))

            ---

            const-string v3, "encode string"

            invoke-static {v3}, La/b/c/c;->a(Ljava/lang/String;)[B

            move-result-object v3

            invoke-direct {v2, v3}, Ljava/lang/String;-><init>([B)V

            ==>

            const-string v2, "decode string"

        '''

        INVOKE_STATIC = 'invoke-static \{[vp]\d+}, L([^;]+);->([^\(]+\(Ljava/lang/String;\))\[B\s+'
        STRING_INIT = 'invoke-direct {[vp]\d+, [vp]\d+}, Ljava\/lang\/String;-><init>\(\[B\)V'

        reg = '\s+' + self.CONST_STRING + '\s+' + INVOKE_STATIC + self.MOVE_RESULT_OBJECT + '\s+' + STRING_INIT
        p = re.compile(reg)



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
                p3 = re.compile(STRING_INIT)
                mro_statement = p3.search(line).group()
                return_variable_name = mro_statement[mro_statement.index('{') + 1:mro_statement.index(',')]

                if id not in target_contexts.keys():
                    target_contexts[id] = [(mtd, line, '\n\n    const-string %s, ' % return_variable_name)]
                else:
                    target_contexts[id].append((mtd, line, '\n\n    const-string %s, ' % return_variable_name))

                if test not in json_list:
                    json_list.append(test)

        if json_list and target_contexts:
            self.optimizations(json_list, target_contexts)

    def optimizations(self, json_list, target_contexts):
        jsons = JSONEncoder().encode(json_list)
        print(jsons)

        with tempfile.NamedTemporaryFile() as fp:
            fp.write(jsons.encode('utf-8'))
            outputs = self.driver.decode(fp.name)
            print(outputs)

        for key in outputs:
            if 'success' in outputs[key]:
                newstr = ''
                for item in outputs[key][1][1:-1].split(','):
                    newstr = newstr + (chr(eval(item)))
                print(newstr)

                for item in target_contexts[key]:
                    old_body = item[0].body
                    target_context = item[1]
                    new_context = item[2] + '"' + newstr + '"'
                    item[0].body = old_body.replace(target_context, new_context)
                    item[0].modified = True
                    self.make_changes = True

        self.smali_files_update()
