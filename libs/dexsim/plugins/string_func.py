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

        self.patterns = [
            # (r'invoke-direct {(.*?), v\d+}, Ljava/lang/String;-><init>\([\[BCI]+\)V', 'Ljava/lang/String;-><init>'),
            (r'invoke-virtual {(.*?)}, Ljava/lang/StringBuilder;->toString\(\)Ljava/lang/String;',
             'Ljava/lang/StringBuilder;->toString()Ljava/lang/String;')
        ]

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> \n')
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

        try:
            self.__process_string_buffer()
        except TIMEOUT_EXCEPTION as ex:
            print(ex)

        try:
            self.__process_string_substring()
        except TIMEOUT_EXCEPTION as ex:
            print(ex)

        # for ptn, mtd_sign in self.patterns:
        #     try:
        #         self.__process(ptn, mtd_sign)
        #     except TIMEOUT_EXCEPTION as ex:
        #         print(ex)

    @timeout(5)
    def __process_new_string(self):
        print('__process_new_string', end=' ')
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

            for line in re.split(r'\n\s', mtd.body):
                # 固定行数
                # 特殊opcode？ const
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
        print(self.make_changes)
        self.smali_files_update()

    @timeout(5)
    def __process_string_valueof(self):
        print('__process_string_valueof', end=' ')
        mtd_sign = 'Ljava/lang/String;->valueOf'
        valueof_ptn = (
            r'invoke-static {(v\d+)}, Ljava/lang/String;->valueOf'
            r'\(Ljava/lang/Object;\)Ljava/lang/String;')
        prog = re.compile(valueof_ptn)

        flag = False
        new_body = []

        for mtd in self.methods:
            if 'valueOf' not in mtd.body:
                continue

            flag = False
            new_body = []
            snippet = []

            index = -1
            lines = re.split(r'\n\s', mtd.body)
            for line in lines:
                index += 1
                new_line = None

                result = prog.search(line)
                if not result:
                    new_body.append(line)
                    continue

                snippet.append(line)
                rtname = result.groups()[0]

                for idx in range(index - 1, -1, -1):
                    if rtname in lines[idx]:
                        snippet.insert(0, lines[idx])
                        break

                snippet.append('return-object %s' % rtname)

                result = self.emu.call(snippet, thrown=False)
                snippet.clear()

                if result:
                    new_line = 'const-string %s, "%s"' % (rtname, result)
                    flag = True
                    if 'const-string %s' % rtname in new_body[-1]:
                        del new_body[-1]
                    new_body.append(new_line)
                else:
                    new_body.append(line)

            if flag:
                mtd.body = '\n'.join(new_body)
                mtd.modified = True
                self.make_changes = True

        print(self.make_changes)
        self.smali_files_update()

    @timeout(5)
    def __process_string_builder(self):
        print('__process_string_builder', end=' ')
        ptn = (
            r'new-instance v\d+, Ljava/lang/StringBuilder;'
            r'[\w\W\s]+?{(v\d+)[.\sv\d]*}, '
            r'Ljava/lang/StringBuilder;->toString\(\)Ljava/lang/String;')
        prog = re.compile(ptn)
        for mtd in self.methods:
            if 'Ljava/lang/StringBuilder;->toString()Ljava/lang/String;' not in mtd.body:
                continue

            flag = False
            new_content = None

            result = prog.finditer(mtd.body)
            for item in result:
                rtname = item.groups()[0]

                old_content = item.group()
                snippet = re.split(r'\n+', old_content)

                snippet.append('return-object %s' % rtname)

                try:
                    result = self.emu.call(snippet)
                # TODO 目前没有比较好的替换办法，如果不抛异常可能会替换掉正常的东西
                except Exception:
                    continue

                if result:
                    new_content = 'const-string %s, "%s"' % (
                        rtname, result)

                if new_content:
                    flag = True
                    mtd.body = mtd.body.replace(old_content, new_content)

            if flag:
                mtd.modified = True
                self.make_changes = True
        print(self.make_changes)
        self.smali_files_update()

    @timeout(5)
    def __process_string_buffer(self):
        print('__process_string_buffer', end=' ')
        ptn = (
            r'new-instance v\d+, Ljava/lang/StringBuffer;'
            r'[\w\W\s]+?{(v\d+)[.\sv\d]*}, '
            r'Ljava/lang/StringBuffer;->toString\(\)Ljava/lang/String;')
        prog = re.compile(ptn)

        for mtd in self.methods:
            if 'Ljava/lang/StringBuffer;->toString()Ljava/lang/String;' not in mtd.body:
                continue

            flag = False
            new_content = None

            result = prog.finditer(mtd.body)
            for item in result:
                rtname = item.groups()[0]

                old_content = item.group()
                snippet = re.split(r'\n+', old_content)
                snippet.append('return-object %s' % rtname)

                try:
                    result = self.emu.call(snippet)
                # TODO 目前没有比较好的替换办法，如果不抛异常可能会替换掉正常的东西
                except Exception:
                    continue

                if result:
                    new_content = 'const-string %s, "%s"' % (
                        rtname, result)

                if new_content:
                    flag = True
                    mtd.body = mtd.body.replace(old_content, new_content)

            if flag:
                mtd.modified = True
                self.make_changes = True

        print(self.make_changes)
        self.smali_files_update()

    @timeout(5)
    def __process_string_substring(self):
        print('__process_string_substring', end=' ')
        ptn = (
            r'invoke-virtual {(.*?), v\d+, v\d+}, '
            r'Ljava/lang/String;->substring\(II\)Ljava/lang/String;')
        prog = re.compile(ptn)

        for mtd in self.methods:
            if 'Ljava/lang/String;->substring(II)Ljava/lang/String;' not in mtd.body:
                continue

            new_content = None

            lines = re.split(r'\n', mtd.body)
            tmp_bodies = lines.copy()

            snippet = []
            index = -1

            for line in lines:
                index += 1
                if 'const' in line:
                    snippet.append(line)
                    continue

                match = prog.search(line)
                if not match:
                    continue

                snippet.append(line)
                rtname = match.groups()[0]
                snippet.append('return-object %s' % rtname)
                result = self.emu.call(snippet, thrown=False)

                if not result:
                    continue

                new_content = 'const-string %s, "%s"' % (rtname, result)
                tmp_bodies[index] = new_content
                mtd.modified = True
                self.make_changes = True

            mtd.body = '\n'.join(tmp_bodies)
        print(self.make_changes)
        self.smali_files_update()

    @timeout(3)
    def __process(self, ptn, mtd_sign):
        print(ptn, mtd_sign)
        prog = re.compile(ptn)

        for mtd in self.methods:
            if mtd_sign not in mtd.body:
                continue

            print(mtd.descriptor)

            lines = re.split(r'\n', mtd.body)
            tmp_bodies = lines.copy()

            snippet = []
            index = -1

            for line in lines:
                index += 1
                if len(snippet) > 100:
                    del snippet[0]
                snippet.append(line)

                # if 'const' in line:
                #     snippet.append(line)
                #     continue

                match = prog.search(line)
                if not match:
                    continue

                print(line)

                # snippet.append(line)
                result = self.emu.call(snippet, trace=True, thrown=False)

                if not result:
                    continue
                print('result:', result)

        #         rtname = match.groups()[0]
        #         new_content = 'const-string %s, "%s"' % (rtname, result)

        #         tmp_bodies[index] = new_content

        #         mtd.modified = True
        #         self.make_changes = True

        #     mtd.body = '\n'.join(tmp_bodies)

        # self.smali_files_update()
