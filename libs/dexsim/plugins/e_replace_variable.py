import re
import logging

from libs.dexsim.plugin import Plugin

__all__ = ["ReplaceVariable"]

logger = logging.getLogger(__name__)


class ReplaceVariable(Plugin):
    '''变量替换

    因为支持smali运算后，这个插件的意义已经不大。
    '''
    name = "ReplaceVariable"
    enabled = False

    def __init__(self, driver, methods, smalidir):
        Plugin.__init__(self, driver, methods, smalidir)
        self.make_changes = False

    def run(self):
        print('Run ' + __name__, end=' ', flush=True)
        self.__process_all()

    def __process_all(self):
        string_ptn = r'\s*(const.*?) v\d+, (.*?)\s*'
        sput_ptn = (r'sput-object [vp]\d+, (.*?)\s+')
        sput_prog = re.compile(string_ptn + sput_ptn)

        # field_sgin:value
        fields = {}

        for sf in self.smalidir:
            for mtd in sf.get_methods():
                for i in sput_prog.finditer(mtd.get_body()):
                    opcode, value, key = i.groups()
                    fields[key] = (opcode, value)

        if not fields:
            return

        sget_ptn = r'sget-object [vp]\d+, '
        for key in fields:
            # Skip array
            if ':[' in key:
                continue
            sget_prog = re.compile(sget_ptn + key)
            for sf in self.smalidir:
                for mtd in sf.get_methods():
                    for item in sget_prog.finditer(mtd.get_body()):
                        line = item.group()
                        old = line

                        # MAYBE
                        # smali const/4 vn, 0x1111，the range of register is 0~15.
                        # if vn>v15, const/4 need to be changed to const/16.
                        new = line.replace(
                            'sget-object', fields[key][0]).replace(key, fields[key][1])

                        mtd.set_body(mtd.get_body().replace(old, new))

                        mtd.set_modified(True)
                        self.make_changes = True
                        sf.set_modified(True)

        self.smali_files_update()
