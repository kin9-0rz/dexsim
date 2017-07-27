import re

from libs.dexsim.plugin import Plugin

__all__ = ["ReplaceVariable"]


class ReplaceVariable(Plugin):
    name = "ReplaceVariable"
    enabled = True

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

        invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->
        append(Ljava/lang/String;)Ljava/lang/StringBuilder;
        ==>
        const-string v3, "string_value"

        invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->
        append(Ljava/lang/String;)Ljava/lang/StringBuilder;
        '''
        SPUT_OBJECT = (r'sput-object [vp]\d+, L[\w\/\d;]+'
                       r'->[\w]+:Ljava/lang/String;')
        SGET_OBJECT = r'sget-object [vp]\d+, '

        p = re.compile(r'\s+' + self.CONST_STRING + r'\s+' + SPUT_OBJECT)

        fields = {}
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                line = i.group()

                start = line.index('"')
                end = line.rindex('"')
                value = line[start:end + 1]

                tp = re.compile(r'L[\w\/\d;]+->[\w]+:Ljava/lang/String;')
                key = tp.search(line).group()

                fields[key] = value

        if len(fields) == 0:
            return

        for key in fields.keys():
            p2 = re.compile(SGET_OBJECT + key)
            for mtd in self.methods:
                for i in p2.finditer(mtd.body):
                    line = i.group()
                    old_content = line
                    new_content = line.replace(
                        'sget-object', 'const-string').replace(key, fields[key])

                    mtd.body = mtd.body.replace(old_content, new_content)
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

        SPUT = r'sput [vp]\d+, L[\w\/\d;]+->[\w]+:I'
        SGET = r'sget [vp]\d+, '

        p = re.compile(r'\s+' + self.CONST_NUMBER + r'\s+' + SPUT)

        fields = {}
        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                line = i.group()

                tmps = line.split()
                opcode = tmps[0]
                value = tmps[2]
                field_sign = tmps[5]

                fields[field_sign] = (opcode, value)

        if not fields:
            return

        for key in fields:
            p2 = re.compile(SGET + key)
            for mtd in self.methods:
                for i in p2.finditer(mtd.body):
                    line = i.group()
                    opcode_name = fields[key][0]
                    register = line.split()[1]
                    value = fields[key][1]
                    idx = opcode_name.index('/')

                    # smali const/4 vn, 0x1111，the range of register is 0~15.
                    # if vn>v15, const/4 need to be changed to const/16.
                    wide = int(opcode_name[idx + 1:])
                    if int(register[1:-1]) > 15 and wide == 4:
                        opcode_name = opcode_name[:idx + 1] + '16'

                    new_content = opcode_name + ' ' + register + ' ' + value
                    old_content = line
                    mtd.body = mtd.body.replace(old_content, new_content)

                    mtd.modified = True
                    self.make_changes = True

        self.smali_files_update()

    def __process_stringbuilder_init(self):
        '''
            const-string v3, "string1"

            invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>
                                                        (Ljava/lang/String;)V

            const-string v3, "_string2"

            ==>

            const-string v3, "string1_string2"
        '''

        ptn = ('invoke-direct \{[vp]\d+, [vp]\d+\}, '
               'Ljava/lang/StringBuilder;-><init>\(Ljava/lang/String;\)V')

        p = re.compile('\s+' + self.CONST_STRING + '\s+' + ptn + '\s+' +
                       self.CONST_STRING + '\s+')

        for mtd in self.methods:
            for i in p.finditer(mtd.body):
                old_content = i.group()

                tmp = old_content.split('"')
                old_value = '"' + tmp[3] + '"'
                new_value = '"' + tmp[1] + tmp[3] + '"'
                index = old_content.rindex('\n\n    const-string ')
                new_content = old_content[index:].replace(old_value, new_value)
                mtd.body = mtd.body.replace(old_content, new_content)
                mtd.modified = True
                self.make_changes = True

        self.smali_files_update()
