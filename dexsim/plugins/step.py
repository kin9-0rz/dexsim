import os
import re
import tempfile
from json import JSONEncoder

import smafile
from dexsim.plugin import Plugin

PLUGIN_CLASS_NAME = "STEP"


# 1. 找到解密函数
# 2. 模拟执行前面可以执行的代码
# 3. 获取解密参数
# 4. 验证解密参数，如果失败，则跳过；如果得到，则继续。
# 5. 初始化，解密对象
# 6. 调用解密函数解密
# 7. 获取解密内容
# 8. 替换解密内容，优化代码

# 存放需要解密的函数模版
regexs = [
    (r'invoke-static {(v\d+?, v\d+?, v\d+?)}, (.*?;)->(.*?)\(III\)Ljava/lang/String;',
     ['I', 'I', 'I']),
    (r'invoke-static {(v\d+?, v\d+?, v\d+?)}, (.*?;)->(.*?)\(SIS\)Ljava/lang/String;',
     ['S', 'I', 'S'])
]


class STEP(Plugin):
    name = PLUGIN_CLASS_NAME
    enabled = False
    version = '0.0.1'
    tname = None
    index = 4

    def __init__(self, driver, smalidir):
        Plugin.__init__(self, driver, smalidir)
        self.results = {}  # 存放解密结果
        self.ptns = []
        self.global_variables = {}  # 全局变量，模拟执行预设值

    def run(self):
        if self.ONE_TIME:
            return
        self.ONE_TIME = True
        print('Run ' + __name__, end=' ', flush=True)

        for item in regexs:
            self.ptns.append((re.compile(item[0], re.MULTILINE), item[1]))

        self.init_global_variables()

        for sf in self.smalidir:
            for mtd in sf.get_methods():
                # print(mtd)
                self._process_mtd(mtd)

        for sf in self.smalidir:
            sf.update()

    def init_global_variables(self):
        """初始化赋值、数组
        """
        sput_reg = r'const/\d+ v\d+?, 0x\w+\s*?sput v\d+?, .*?;->.*?:I'
        sput_ptn = re.compile(sput_reg, flags=re.MULTILINE)

        def sput_x(body):
            for item in sput_ptn.finditer(body):
                self.emu.call(item.group().split('\n\n'))
                for k, v in self.emu.vm.variables.items():
                    if ';->' in k:
                        self.global_variables[k] = v

        arr_reg = r'const/\d+? v\d+?, 0x\w+?\s*?new-array v\d+?, v\d+?, \[S\s*?fill-array-data v\d+?, (:array_\w+)\s*?sput-object v\d+?, .*?;->.*?:\[S'
        arr_ptn = re.compile(arr_reg, re.MULTILINE)
        arr_data_reg = r'{}\s*.array-data[\w\W\s]+.end array-data'

        def arr_x(body):
            for item in arr_ptn.finditer(body):
                snippet = item.group().split('\n')
                start = item.groups()[0]
                res = re.search(arr_data_reg.format(start), body, re.M)
                snippet.extend(res.group().split('\n'))
                self.emu.call(snippet)
                if not self.emu.vm.result:
                    continue
                for k, v in self.emu.vm.variables.items():
                    if ';->' in k:
                        self.global_variables[k] = v

        for sf in self.smalidir:
            for mtd in sf.get_methods():
                if '<clinit>' not in mtd.get_name():
                    break
                body = mtd.get_body()
                sput_x(body)
                arr_x(body)

    @staticmethod
    def argument_names(args):
        """自动转换smali中的方法参数为数组

        Args:
            args (TYPE): Description
        """
        res = []
        for item in args.split(','):
            res.append(item.strip())
        return res

    def match(self, line):
        for p in self.ptns:
            m = p[0].search(line)
            if m:
                r = m.groups()
                return r[0], r[1], r[2], p[1]
        return False, False, False, False

    def gen_arguments(self, args, protos):
        ans = self.argument_names(args)
        arguments = []
        i = 0
        for vname in ans:
            value = self.emu.vm.variables.get(vname, None)
            if value is None:
                print(protos[i], value, self.convert_args(protos[i], value))
                raise Exception
            arguments.append(self.convert_args(protos[i], value))
            i += 1
        return arguments

    def _process_mtd(self, mtd):
        body = mtd.get_body()
        lines = body.split('\n')

        ops = [
            'sput',
            'aput',
            'new-array',
            'fill-array-data',
            'if-',
            'invoke-virtual',
            ':try_end_',
            '.catchall',
            ':goto_',
            ':cond_',
            'move-exception',
            'move-object'
        ]

        def skip(op):
            """跳过不执行的opcode

            Args:
                op (TYPE): opcode

            Returns:
                TYPE: True表示跳过，False表示不跳过
            """
            for o in ops:
                if o in op:
                    return True

        def decrypt(args, cname, mname, protos, snippet):
            self.emu.call(
                snippet[:-1], args=self.global_variables, cv=True, thrown=True)
            # print(self.emu.vm.variables)

            # 生成解密参数
            try:
                arguments = self.gen_arguments(args, protos)
            except Exception:
                print(snippet[:-2])

                for item in new_lines[-20:]:
                    print(item)
                print(self.emu.vm.variables)
                print(args, protos)
                return
            cname = smafile.smali2java(cname)
            json_item = self.get_json_item(cname, mname, arguments)
            # print(json_item)
            mid = json_item['id']
            rtn_name = pis[1]

            if mid not in self.results:
                self.json_list.append(json_item)
                self.decode(mid)

            return mid

        snippet = []
        is_decode = False
        protos = None
        cname = None
        mname = None
        args = None
        mid = None
        new_lines = []
        for line in lines:
            if not line:
                continue
            # print(line.split())
            new_lines.append(line)

            pis = line.split()
            op = pis[0]
            if is_decode:
                is_decode = False
                if 'move-result-object' in op:
                    rtn_name = pis[1]
                    new_lines[-2] = 'const-string {}, "{}"'.format(rtn_name, self.results[mid])
                    self.make_changes = True
                    mtd.set_modified(True)
                else:
                    new_lines[-2] = 'const-string v0, "Dexsim"'
                    new_lines[-1] = 'const-string v1, "{}"'.format(self.results[mid])
                    new_lines.append('invoke-static {{v0, v1}}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I')
                    new_lines.append(line)
                snippet.clear()
                continue

            # 跳过执行的Opcode
            if skip(op):
                snippet.clear()
                continue

            # try 语句之前，会有一些运算，所以，仅仅过滤掉该语句即可。
            if ':try_start_' in op:
                continue

            if 'invoke-static' not in op:
                snippet.append(line)
                continue

            # 只有invoke-static语句才进行匹配
            args, cname, mname, protos = self.match(line)
            if not cname:
                snippet.clear()
                continue
            snippet.append(line)
            is_decode = True

            # 直接解密，之后，再处理
            mid = decrypt(args, cname, mname, protos, snippet)

        if self.make_changes:
            new_body = '\n'.join(new_lines) + '\n'
            mtd.set_body(new_body)

    def decode(self, mid):
        """解密，并且存放解密结果

        Args:
            mid (str): 指定的解密内容ID

        Returns:
            None
        """
        if not self.json_list:
            return
        print('.', end='', flush=True)

        jsons = JSONEncoder().encode(self.json_list)

        outputs = {}
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tfile:
            tfile.write(jsons)
        outputs = self.driver.decode(tfile.name)
        os.unlink(tfile.name)

        if not outputs:
            return

        # print(outputs)
        self.results[mid] = outputs[mid][0]
        self.json_list.clear()
