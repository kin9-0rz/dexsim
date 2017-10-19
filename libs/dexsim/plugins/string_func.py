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

    def __init__(self, driver, methods, smalidir):
        self.emu = Emulator()
        Plugin.__init__(self, driver, methods, smalidir)
        self.make_changes = False

        self.patterns = [
            (
                r'invoke-direct {(v\d+), v\d+}, '
                r'Ljava/lang/String;-><init>\([\[BCI]+\)V',
                'Ljava/lang/String;-><init>'
            ),
            (
                r'invoke-static {(v\d+)}, Ljava/lang/String;->valueOf'
                r'\(Ljava/lang/Object;\)Ljava/lang/String;',
                'Ljava/lang/String;->valueOf'
            ),
            (
                r'invoke-virtual {(v\d+)}, '
                r'Ljava/lang/StringBuilder;->toString\(\)Ljava/lang/String;',
                'Ljava/lang/StringBuilder;->toString()Ljava/lang/String;'
            ),
            (
                r'invoke-virtual {(v\d+)}, '
                r'Ljava/lang/StringBuffer;->toString\(\)Ljava/lang/String;',
                'Ljava/lang/StringBuffer;->toString()Ljava/lang/String;'
            ),
            (
                r'invoke-virtual {(.*?), v\d+, v\d+}, '
                r'Ljava/lang/String;->substring\(II\)Ljava/lang/String;',
                'Ljava/lang/String;->substring(II)Ljava/lang/String;'
            )
        ]

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> \n')

        for ptn, mtd_filter in self.patterns:
            try:
                self._process(ptn, mtd_filter)
            except TIMEOUT_EXCEPTION as ex:
                print(ex)

    @timeout(3)
    def _process(self, ptn, mtd_filter):
        prog = re.compile(ptn)

        arr_data_prog = re.compile(self.ARRAY_DATA_PATTERN)

        for sf in self.smalidir:
            for mtd in sf.get_methods():
                if mtd_filter not in mtd.get_body():
                    continue

                # 如果存在数组
                array_data_content = []
                result = arr_data_prog.search(mtd.get_body())
                if result:
                    array_data_content = re.split(r'\n\s', result.group())

                flag = False
                new_body = []
                snippet = []
                args = {}
                for line in re.split(r'\n', mtd.get_body()):
                    snippet.append(line)

                    result = prog.search(line)
                    if not result:
                        new_body.append(line)
                        continue
                    rtname = result.groups()[0]

                    snippet.append('return-object %s' % rtname)
                    snippet.extend(array_data_content)

                    args.update(self.pre_process(snippet))
                    self.emu.call(snippet, args=args, thrown=False)
                    args = self.emu.vm.variables

                    result = self.emu.vm.result

                    if result:
                        flag = True
                        if not isinstance(result, str):
                            result = str(result)

                        new_line = 'const-string %s, "%s"' % (
                            rtname, result.encode('unicode-escape').decode())
                        if 'array' in new_body[-2]:
                            del new_body[-1]
                            del new_body[-1]
                        new_body.append(new_line)
                    else:
                        new_body.append(line)

                    snippet.clear()

                if flag:
                    mtd.set_body('\n'.join(new_body))
                    mtd.set_modified(True)
                    self.make_changes = True
            self.smali_files_update()
