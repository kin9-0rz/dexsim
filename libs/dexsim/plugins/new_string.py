# coding:utf-8

import re

from libs.dexsim.plugin import Plugin
'''

'''

__all__ = ["NEW_STRING"]


class NEW_STRING(Plugin):

    name = "NEW_STRING"
    version = '0.0.1'

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self.__process_new_string()

    def __process_new_string(self):
        '''
            new String(byte[]{})

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

            const-string v3, "aHR0cDovL2FuZHJvaWQuZXZpbHFpbi5jb20vbXlzZWxmXzIucGhw"

        '''
        NEW_ARRAY = 'new-array [vp]\d+, [vp]\d+, \[B'
        FILL_ARRAY_DATA = 'fill-array-data [vp]\d+, :array_[\w\d]+'
        NEW_INSTANCE = 'new-instance [vp]\d+, Ljava\/lang\/String;'
        STRING_INIT = 'invoke-direct {[vp]\d+, [vp]\d+}, Ljava\/lang\/String;-><init>\(\[B\)V'

        # print('\s+' + self.CONST_NUMBER + '\s+' + NEW_ARRAY + '\s+' +
        #       FILL_ARRAY_DATA + '\s+((' + NEW_INSTANCE + ')\s+)+')

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
