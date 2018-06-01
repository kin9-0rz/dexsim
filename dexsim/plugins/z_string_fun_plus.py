"""
字符串内置函数
"""
import logging
import re

from timeout3 import TIMEOUT_EXCEPTION, timeout

from ..plugin import Plugin

logger = logging.getLogger(__name__)

__all__ = ["STRING_FUN_PLUS"]


class STRING_FUN_PLUS(Plugin):
    '''
    模拟执行字符串相关函数

    String, StringBuilder, StringBuffer等。
    '''
    name = "STRING_FUN_PLUS"
    enabled = True

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
        print('Run ' + __name__, end=' ', flush=True)
        self.project_a()

    def project_a(self):
        mset = set(['<clinit>', '<init>'])
        for sf in self.smalidir:
            for mtd in sf.get_methods():
                # field value 插件已经处理好了，不需要再次处理
                if mtd.get_name() in mset:
                    continue

                body = mtd.get_body()
                for k in self.progs:
                    if k in mtd.get_body():
                        break
                else:
                    continue
                array_snippet = self.get_array_snippet(body)
                try:
                    flag, new_body = self.process_body(body, array_snippet)
                except TIMEOUT_EXCEPTION:
                    continue

                if flag:
                    mtd.set_body('\n'.join(new_body))
                    mtd.set_modified(True)
                    self.make_changes = True

        self.smali_files_update()

    @timeout(1)
    def process_body(self, body, arrs):
        lines = re.split(r'\n', body)

        flag = False
        new_body = []
        snippet = []
        args = {}
        for line in lines:
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

            snippet.append('return-object %s' % rtname)
            snippet.extend(arrs)
            args.update(self.pre_process(snippet))

            self.emu.call(snippet, args=args, thrown=False)

            args = self.emu.vm.variables
            result = self.emu.vm.result

            if result:
                flag = True
                if not isinstance(result, str):
                    result = str(result)

                new_line = 'const-string %s, "%s"' % (rtname, result)
                if 'array' in new_body[-2]:
                    del new_body[-1]
                    del new_body[-1]
                new_body.append(new_line)
            else:
                new_body.append(line)

            snippet.clear()

        return (flag, new_body)

    def _process(self, ptn, mtd_filter):

        prog = re.compile(ptn)

        for sf in self.smalidir:
            for mtd in sf.get_methods():
                body = mtd.get_body()
                if mtd_filter not in body:
                    continue
                try:
                    self.proc_mtd(mtd, prog)
                except TIMEOUT_EXCEPTION:
                    pass
        self.smali_files_update()

    def get_array_snippet(self, mtd_body):
        result = self.arr_data_prog.search(mtd_body)
        if result:
            return re.split(r'\n\s', result.group())
        else:
            return []

    @timeout(1)
    def proc_mtd(self, mtd, prog):
        # 如果存在数组，则抽取数组部分的smali代码
        array_data_content = []
        result = self.arr_data_prog.search(mtd.get_body())
        if result:
            array_data_content = re.split(r'\n\s', result.group())

        flag = False
        new_body = []
        snippet = []
        args = {}
        lines = re.split(r'\n', mtd.get_body())

        for line in lines:
            snippet.append(line)

            result = prog.search(line)
            if not result:
                # 如果smali代码存在非字符串调用，则清理所有代码
                if line.startswith('invoke-') and 'Ljava/lang/String' not in line:
                    snippet.clear()
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

                new_line = 'const-string %s, "%s"' % (rtname, result)
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

    @timeout(1)
    def run_snippet(self, snippet, args):
        self.emu.call(snippet, args=args, thrown=False)
