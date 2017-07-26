import re

from libs.dexsim.plugin import Plugin
from smaliemu.emulator import Emulator

__all__ = ["NEW_STRING"]


class NEW_STRING(Plugin):
    name = "NEW_STRING"
    enabled = False

    def __init__(self, driver, methods, smali_files):
        self.emu = Emulator()
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self.__process_new_str()
        self.__process_to_string_builder()
        self.__process_to_string_buffer()

    def __process_new_str(self):
        """
        There are two cases:

        1. The augument is a numerical constant.
        2. The augument is in the :array_[\w\d]+
        """
        for mtd in self.methods:
            if 'Ljava/lang/String;-><init>([B)V' not in mtd.body:
                continue

            arr_data_prog = re.compile(self.ARRAY_DATA_PATTERN)

            flag = False
            new_body = []
            new_str_ptn = (r'invoke-direct {(v\d+), v\d+}, '
                           'Ljava/lang/String;-><init>\([\[BCI]+\)V')
            new_str_prog = re.compile(new_str_ptn)
            for line in re.split(r'\n+', mtd.body):
                new_line = None
                if 'Ljava/lang/String;-><init>' in line:
                    result = new_str_prog.search(line)
                    if not result:
                        new_body.append(line)
                        continue
                    return_register_name = result.groups()[0]

                    tmp = new_body.copy()
                    tmp.append(line)
                    tmp.append('return-object %s' % return_register_name)

                    result = arr_data_prog.search(mtd.body)
                    if result:
                        array_data_content = re.split(r'\n+', result.group())
                        tmp.extend(array_data_content)

                    decoded_string = (self.emu.call(tmp, thrown=False))
                    if decoded_string:
                        new_line = 'const-string %s, "%s"' % (
                            return_register_name, decoded_string)

                if new_line:
                    flag = True
                    new_body.append(new_line)
                else:
                    new_body.append(line)

            if flag:
                mtd.body = '\n'.join(new_body)
                mtd.modified = True
                self.make_changes = True

        self.smali_files_update()

    def __process_to_string_builder(self):
        to_string_re = (
            r'new-instance v\d+, Ljava/lang/StringBuilder;'
            '[\w\W\s]+?{(v\d+)[.\sv\d]*}, '
            'Ljava/lang/StringBuilder;->toString\(\)Ljava/lang/String;')
        prog3 = re.compile(to_string_re)
        for mtd in self.methods:

            if 'const-string' not in mtd.body:
                continue
            if 'Ljava/lang/StringBuilder;-><init>' not in mtd.body:
                continue
            if 'Ljava/lang/StringBuilder;->toString()Ljava/lang/String;'\
               not in mtd.body:
                continue

            flag = False
            new_content = None

            result = prog3.finditer(mtd.body)

            for item in result:
                return_register_name = item.groups()[0]
                old_content = item.group()
                arr = re.split(r'\n+', old_content)
                arr.append('return-object %s' % return_register_name)
                try:
                    decoded_string = self.emu.call(arr)

                    if len(self.emu.vm.exceptions) > 0:
                        continue

                    if decoded_string:
                        new_content = 'const-string %s, "%s"' % (
                            return_register_name, decoded_string)
                except Exception as e:
                    continue

                if new_content:
                    flag = True
                    mtd.body = mtd.body.replace(old_content, new_content)

            if flag:
                mtd.modified = True
                self.make_changes = True

        self.smali_files_update()

    def __process_to_string_buffer(self):
        to_string_re = (
            r'new-instance v\d+, Ljava/lang/StringBuffer;'
            '[\w\W\s]+?{(v\d+)[.\sv\d]*}, '
            'Ljava/lang/StringBuffer;->toString\(\)Ljava/lang/String;')
        prog3 = re.compile(to_string_re)
        for mtd in self.methods:
            if 'const-string' not in mtd.body:
                continue
            if 'Ljava/lang/StringBuilder;-><init>' not in mtd.body:
                continue
            if 'Ljava/lang/StringBuilder;->toString()Ljava/lang/String;' not\
               in mtd.body:
                continue

            flag = False
            new_content = None

            result = prog3.finditer(mtd.body)

            for item in result:
                return_register_name = item.groups()[0]
                old_content = item.group()
                arr = re.split(r'\n+', old_content)
                arr.append('return-object %s' % return_register_name)
                try:
                    decoded_string = self.emu.call(arr)

                    if len(self.emu.vm.exceptions) > 0:
                        continue

                    if decoded_string:
                        new_content = 'const-string %s, "%s"' % (
                            return_register_name, decoded_string)
                except Exception as e:
                    continue

                if new_content:
                    flag = True
                    mtd.body = mtd.body.replace(old_content, new_content)

            if flag:
                mtd.modified = True
                self.make_changes = True

        self.smali_files_update()
