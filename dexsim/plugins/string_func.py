import re

from smafile import SmaliLine
from timeout3 import TIMEOUT_EXCEPTION, timeout

from dexsim.plugin import Plugin

PLUGIN_CLASS_NAME = "STRING_FUNC"


class STRING_FUNC(Plugin):
    '''
    模拟执行字符串相关函数

    这个插件针对的是，参数是能够直接从smali文件中获取的情况。

    否则，就走Step by Step插件。

    String, StringBuilder, StringBuffer等。
    '''
    name = "STRING_FUNC"
    enabled = False 
    index = 1
    ONE_TIME = False

    def __init__(self, driver, smalidir):
        Plugin.__init__(self, driver, smalidir)
        self.make_changes = False
        self.arr_data_prog = re.compile(self.ARRAY_DATA_PATTERN)
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

        self.progs = {}
        for ptn, mtd_filter in self.patterns:
            self.progs[mtd_filter] = re.compile(ptn)

    def run(self):
        if self.ONE_TIME:
            return
        print('Run ' + __name__, end=' ', flush=True)
        self.processes()
        self.ONE_TIME = True

    @staticmethod
    def skip_init(mtd_name):
        '''
        FieldValue 插件已经处理，不需要再次处理
        '''
        mset = set(['<clinit>', '<init>'])
        return mtd_name in mset

    def processes(self):

        for sf in self.smalidir:
            for mtd in sf.get_methods():
                if self.skip_init(mtd.get_name()):
                    continue

                body = mtd.get_body()
                for k in self.progs:
                    if k in mtd.get_body():
                        break
                else:
                    continue

                try:
                    flag, new_body = self.process_body(body)
                except TIMEOUT_EXCEPTION:
                    continue

                if not flag:
                    continue

                mtd.set_body('\n'.join(new_body))
                mtd.set_modified(True)
                self.make_changes = True

        self.smali_files_update()

    @timeout(1)
    def process_body(self, body):
        '''
        返回(结果、新的方法体)
        '''
        array_snippet = self.get_array_snippet(body)

        lines = re.split(r'\n', body)

        flag = False
        new_body = []
        snippet = []
        args = {}
        for line in lines:
            if not line:
                continue

            if 'move-result-object' in line and 'const-string' in new_body[-1]:
                # 这种情况会导致反编译工具反编译失败
                # const-string v9, "bytes="
                # move-result-object v9

                v0 = SmaliLine.parse(line)
                vx, string_id = SmaliLine.parse(new_body[-1])

                if v0 != vx:
                    new_line = 'const-string {}, "{}"'.format(v0, string_id)
                    new_body[-1] = new_line
                continue

            snippet.append(line)

            for _, prog in self.progs.items():
                result = prog.search(line)
                if result:
                    break
            else:
                # 如果smali代码存在非字符串调用，则清理所有代码
                if 'invoke-' in line and ', Ljava/lang/String' not in line:
                    snippet.clear()
                new_body.append(line)
                continue

            rtname = result.groups()[0]

            snippet.append('return-object {}'.format(rtname))
            snippet.extend(array_snippet)
            args.update(self.pre_process(snippet))

            self.emu.call(snippet, args=args, thrown=False)
            args = self.emu.vm.variables
            result = self.emu.vm.result

            if result:
                flag = True
                if not isinstance(result, str):
                    result = str(result)
                new_line = 'const-string {}, "{}"'.format(rtname, result)
                if 'array' in new_body[-2]:
                    del new_body[-1]
                    del new_body[-1]
                new_body.append(new_line)
            else:
                new_body.append(line)

            snippet.clear()

        return (flag, new_body)

    def get_array_snippet(self, mtd_body):
        result = self.arr_data_prog.search(mtd_body)
        if result:
            return re.split(r'\n\s', result.group())
        else:
            return []
