import re

from smaliemu.emulator import Emulator

from libs.dexsim.plugin import Plugin
from libs.dexsim.timeout import timeout
from libs.dexsim.timeout import TIMEOUT_EXCEPTION


__all__ = ["STRING_FUNC"]


class STRING_FUNC(Plugin):
    '''
    模拟执行字符串相关函数

    String, StringBuilder, StringBuffer等。
    '''
    name = "STRING_FUNC"
    enabled = True

    def __init__(self, driver, methods, smali_files):
        self.emu = Emulator()
        Plugin.__init__(self, driver, methods, smali_files)

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        try:
            self.__process_new_string()
        except TIMEOUT_EXCEPTION as ex:
            print(ex)

        try:
            self.__process_string_valueof()
        except TIMEOUT_EXCEPTION as ex:
            print(ex)

        try:
            self.__process_string_builder()
        except TIMEOUT_EXCEPTION as ex:
            print(ex)

        self.__process_string_buffer()

    @timeout(5)
    def __process_new_string(self):
        """new String()"""
        new_str_ptn = (r'invoke-direct {(v\d+), v\d+}, '
                       r'Ljava/lang/String;-><init>\([\[BCI]+\)V')
        new_str_prog = re.compile(new_str_ptn)

        for mtd in self.methods:
            if 'Ljava/lang/String;-><init>' not in mtd.body:
                continue

            arr_data_prog = re.compile(self.ARRAY_DATA_PATTERN)

            flag = False
            new_body = []
            snippet = []

            for line in re.split(r'\n\s+', mtd.body):
                if len(snippet) > 10:
                    del snippet[0]
                snippet.append(line)

                result = new_str_prog.search(line)
                if not result:
                    new_body.append(line)
                    continue
                rtname = result.groups()[0]

                snippet.append('return-object %s' % rtname)

                result = arr_data_prog.search(mtd.body)
                if result:
                    array_data_content = re.split(r'\n+', result.group())
                    snippet.extend(array_data_content)
                result = self.emu.call(snippet, thrown=False)

                if result:
                    flag = True
                    new_line = 'const-string %s, "%s"' % (rtname, result)
                    if 'array' in new_body[-2]:
                        del new_body[-1]
                        del new_body[-1]
                    new_body.append(new_line)
                else:
                    new_body.append(line)

                snippet.clear()

            if flag:
                mtd.body = '\n'.join(new_body)
                mtd.modified = True
                self.make_changes = True

        self.smali_files_update()

    @timeout(5)
    def __process_string_valueof(self):
        orig_mtd = 'Ljava/lang/String;->valueOf'
        valueof_ptn = (
            r'invoke-static {(v\d+)}, Ljava/lang/String;->valueOf'
            r'\(Ljava/lang/Object;\)Ljava/lang/String;')
        prog = re.compile(valueof_ptn)

        flag = False
        new_body = []

        for mtd in self.methods:
            if orig_mtd not in mtd.body:
                continue

            flag = False
            new_body = []
            snippet = []

            for line in re.split(r'\n\s+', mtd.body):
                new_line = None
                if len(snippet) > 10:
                    del snippet[0]
                snippet.append(line)

                result = prog.search(line)
                if not result:
                    new_body.append(line)
                    continue

                rtname = result.groups()[0]

                snippet.append('return-object %s' % rtname)

                result = self.emu.call(snippet, thrown=False)
                if result:
                    new_line = 'const-string %s, "%s"' % (rtname, result)
                    flag = True
                    if 'const' in new_body[-1]:
                        del new_body[-1]
                    new_body.append(new_line)
                else:
                    new_body.append(line)

            if flag:
                mtd.body = '\n'.join(new_body)
                mtd.modified = True
                self.make_changes = True

        self.smali_files_update()

    @timeout(5)
    def __process_string_builder(self):
        ptn = (
            r'new-instance v\d+, Ljava/lang/StringBuilder;'
            r'[\w\W\s]+?{(v\d+)[.\sv\d]*}, '
            r'Ljava/lang/StringBuilder;->toString\(\)Ljava/lang/String;')
        prog = re.compile(ptn)
        for mtd in self.methods:
            if 'Ljava/lang/StringBuilder;->toString()Ljava/lang/String;'\
               not in mtd.body:
                continue

            flag = False
            new_content = None

            result = prog.finditer(mtd.body)
            for item in result:
                rtname = item.groups()[0]

                old_content = item.group()
                snippet = re.split(r'\n+', old_content)
                snippet.append('return-object %s' % rtname)
                result = self.emu.call(snippet, thrown=False)

                if result:
                    new_content = 'const-string %s, "%s"' % (
                        rtname, result)

                if new_content:
                    flag = True
                    mtd.body = mtd.body.replace(old_content, new_content)

            if flag:
                mtd.modified = True
                self.make_changes = True

        self.smali_files_update()

    @timeout(5)
    def __process_string_buffer(self):
        ptn = (
            r'new-instance v\d+, Ljava/lang/StringBuffer;'
            r'[\w\W\s]+?{(v\d+)[.\sv\d]*}, '
            r'Ljava/lang/StringBuffer;->toString\(\)Ljava/lang/String;')
        prog = re.compile(ptn)

        for mtd in self.methods:
            if 'Ljava/lang/StringBuffer;->toString()Ljava/lang/String;'\
               not in mtd.body:
                continue

            flag = False
            new_content = None

            result = prog.finditer(mtd.body)
            for item in result:
                rtname = item.groups()[0]

                old_content = item.group()
                snippet = re.split(r'\n+', old_content)
                snippet.append('return-object %s' % rtname)
                result = self.emu.call(snippet, thrown=False)

                if result:
                    new_content = 'const-string %s, "%s"' % (
                        rtname, result)

                if new_content:
                    flag = True
                    mtd.body = mtd.body.replace(old_content, new_content)

            if flag:
                mtd.modified = True
                self.make_changes = True

        self.smali_files_update()
