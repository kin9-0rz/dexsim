# coding:utf-8

import sys
import hashlib
from json import JSONEncoder
import re

from libs.dexsim.plugin import Plugin

__all__ = ["ReplaceVariable"]


class ReplaceVariable(Plugin):

    name = "ReplaceVariable"
    version = '0.0.2'

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self.__process_string()
        self.__process_int()
        self.__process_stringbuilder_init()

    def __process_string(self):
        '''
            const-string v0, "string_value"
            sput-object v0, Ltest/test/cls;->func:Ljava/lang/String;

            sget-object v3, Ltest/test/cls;->func:Ljava/lang/String;
            invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
            ==>
            const-string v3, "string_value"
            invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
        '''

        SPUT_OBJECT = 'sput-object [vp]\d+, L[\w\/\d;]+->[\w]+:Ljava/lang/String;'
        SGET_OBJECT = 'sget-object [vp]\d+, '

        p = re.compile('\s+' + self.CONST_STRING + '\s+' + SPUT_OBJECT)

        fields = {}
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                line = i.group()

                start = line.index('"')
                end = line.rindex('"')
                value = line[start:end + 1]

                tp = re.compile('L[\w\/\d;]+->[\w]+:Ljava/lang/String;')
                key = tp.search(line).group()

                fields[key] = value

        if len(fields) == 0:
            return

        for key in fields.keys():
            p2 = re.compile(SGET_OBJECT + key)
            for mtd in self.methods:
                for i in p2.finditer(mtd.body):
                    line = i.group()
                    old_context = line
                    new_context = line.replace(
                        'sget-object', 'const-string').replace(key, fields[key])
                    mtd.body = mtd.body.replace(old_context, new_context)
                    mtd.modified = True
                    self.make_changes = True

        self.smali_files_update()

    def __process_int(self):
        '''
            const/16 v0, 0xe2
            sput v0, Lcom/skt/pig/UserInterface;->f:I


            sget v3, Lcom/skt/pig/UserInterface;->f:
            ==>
            const/16 v3, 0xe2
        '''

        SPUT = 'sput [vp]\d+, L[\w\/\d;]+->[\w]+:I'
        SGET = 'sget [vp]\d+, '

        p = re.compile('\s+' + self.CONST_NUMBER + '\s+' + SPUT)

        fields = {}
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                line = i.group()

                tmps = line.split()
                opcode = tmps[0]
                value = tmps[2]
                field_sign = tmps[5]

                fields[field_sign] = (opcode, value)

        if len(fields) == 0:
            return

        for key in fields.keys():
            p2 = re.compile(SGET + key)
            for mtd in self.methods:
                for i in p2.finditer(mtd.body):
                    line = i.group()
                    opcode_name = fields[key][0]
                    register = line.split()[1]
                    value = fields[key][1]
                    idx = opcode_name.index('/')

                    # smali const/4 vn, 0x1111，寄存器的范围只能是0~15.
                    # 所以，如果n大于15的时候，则需要调整为const/16。
                    wide = int(opcode_name[idx+1:])
                    if int(register[1:-1]) > 15 and wide == 4:
                        opcode_name = opcode_name[:idx+1] + '16'

                    new_context = opcode_name + ' ' + register + ' ' + value
                    old_context = line
                    mtd.body = mtd.body.replace(old_context, new_context)

                    mtd.modified = True
                    self.make_changes = True

        self.smali_files_update()

    def __process_stringbuilder_init(self):
        '''

            const-string v3, "string1"

            invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

            const-string v3, "_string2"

            ==>

            const-string v3, "string1_string2"
        '''
        INVOKE_DIRECT_STRING_BUILDER = 'invoke-direct \{[vp]\d+, [vp]\d+\}, Ljava/lang/StringBuilder;-><init>\(Ljava/lang/String;\)V'

        p = re.compile('\s+' + self.CONST_STRING + '\s+' + INVOKE_DIRECT_STRING_BUILDER + '\s+' + self.CONST_STRING + '\s+')

        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                old_context = i.group()

                tmp = old_context.split('"')
                old_value = '"' + tmp[3] + '"'
                new_value = '"' + tmp[1] + tmp[3] + '"'
                index = old_context.rindex('\n\n    const-string ')
                new_context = old_context[index:].replace(old_value, new_value)
                mtd.body = mtd.body.replace(old_context, new_context)
                mtd.modified = True
                self.make_changes = True

        self.smali_files_update()
