import re

from libs.dexsim.plugin import Plugin

__all__ = ["ReplaceVariable"]


class ReplaceVariable(Plugin):
    '''变量替换'''
    name = "ReplaceVariable"
    enabled = False

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self.__process_all()
        # self.__process_stringbuilder_init()

    def __process_all(self):
        string_ptn = r'\s*(const.*?) v\d+, (.*?)\s*'
        sput_ptn = (r'sput-object [vp]\d+, (.*?)\s+')
        prog1 = re.compile(string_ptn + sput_ptn)

        # field_sgin:value
        fields = {}
        for mtd in self.methods:
            for i in prog1.finditer(mtd.body):
                opcode, value, key = i.groups()
                fields[key] = (opcode, value)

        if not fields:
            return

        sget_ptn = r'sget-object [vp]\d+, '
        for key in fields:
            # Skip array
            if ':[' in key:
                continue
            prog2 = re.compile(sget_ptn + key)
            for mtd in self.methods:
                for item in prog2.finditer(mtd.body):
                    line = item.group()
                    old_content = line

                    # MAYBE
                    # smali const/4 vn, 0x1111，the range of register is 0~15.
                    # if vn>v15, const/4 need to be changed to const/16.

                    new_content = line.replace(
                        'sget-object', fields[key][0]).replace(key, fields[key][1])

                    # print(old_content, '->', new_content)

                    mtd.body = mtd.body.replace(old_content, new_content)
                    mtd.modified = True
                    self.make_changes = True

        self.smali_files_update()

    def __process_stringbuilder_init(self):
        ''' 这个方法考虑使用运算的方式解决
            const-string v3, "string1"

            invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>
                                                        (Ljava/lang/String;)V

            const-string v3, "_string2"

            ==>

            const-string v3, "string1_string2"
        '''

        ptn = (r'invoke-direct \{[vp]\d+, [vp]\d+\}, '
               r'Ljava/lang/StringBuilder;-><init>\(Ljava/lang/String;\)V')

        p = re.compile(r'\s+' + self.CONST_STRING + r'\s+' + ptn + r'\s+' +
                       self.CONST_STRING + r'\s+')

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
