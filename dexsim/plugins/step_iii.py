import os
import re
import tempfile
from json import JSONEncoder

from colorclass.color import Color
from dexsim import DEBUG_MODE
from dexsim.plugin import Plugin

PLUGIN_CLASS_NAME = "STEP_III"

# Lo/r/g/ন$Ⅱ;->ᖬ:I 固定为0

# sget v2, Lo/r/g/ন$Ⅱ;->ᖬ:I
# or-int/lit16 v2, v2, 0x9a
# int-to-short v2, v2
# sget v3, Lo/r/g/ন$Ⅱ;->ᖬ:I
# or-int/lit8 v3, v3, 0xd
# int-to-byte v3, v3
# sget v5, Lo/r/g/ন$Ⅱ;->ᖬ:I
# or-int/lit16 v5, v5, 0x144c
# int-to-short v5, v5
# invoke-static {v2, v3, v5}, Lo/r/g/ন$Ⅱ;->ᖽ(III)Ljava/lang/String;
# move-result-object v2
#
# =>
#
# 替换为 const-string v0 "解密内容"
# 两步解密
# 1. 模拟计算前面的值
# 2. 调用解密函数解密
# 3. 替换解密内容


class STEP_III(Plugin):
    name = PLUGIN_CLASS_NAME
    enabled = False
    tname = None
    index = 4

    def __init__(self, driver, smalidir):
        Plugin.__init__(self, driver, smalidir)
        self.results = {}   # 存放解密结果

    def run(self):
        if self.ONE_TIME:
            return
        self.ONE_TIME = True
        print('Run ' + __name__, end=' ', flush=True)

        regex = (
            r'(sget [.\s\S]{50,300})'
            r'invoke-static {(v\d+?, v\d+?, v\d+?)}, (.*?;)->(.*?)\(III\)Ljava/lang/String;\s*?'
            r'move-result-object (v\d+)'
        )

        print(regex)
        ptn = re.compile(regex, re.MULTILINE)
        # print(ptn)
        for sf in self.smalidir:
            for mtd in sf.get_methods():
                print('----->>>>>>', mtd)
                self._process_mtd(mtd, ptn)

        self.optimize()

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

    def clint():
        pass

    def _process_mtd(self, mtd, ptn):
        if DEBUG_MODE:
            print('\n', '+' * 100)
            print('Starting to decode ...')
            print(Color.green(mtd))

        body = mtd.get_body()
        for item in ptn.finditer(body):
            old_content = item.group()  # 匹配到的内容，用来替换
            print(old_content)
            # args: 解密参数
            # cname：解密类
            # mname：解密方法
            # rtn_name：最后返回的字符串寄存器，new String的寄存器名字
            part, args, cname, mname, rtn_name = item.groups()
            snippet = part.split('\n\n')

            # TODO 自动初始化，静态变量，静态数组等等。后续用于片段计算，用到。

            # TODO 模拟执行代码片段
            self.emu.call(
                snippet, args={'Lo/r/g/ন$Ⅱ;->ᖬ:I': 0}, cv=True, thrown=True)

            # 转化解密参数
            ans = self.argument_names(args)
            v1 = self.emu.vm.variables.get(ans[0], None)
            v2 = self.emu.vm.variables.get(ans[1], None)
            v3 = self.emu.vm.variables.get(ans[2], None)
            if v1 is None or v2 is None or v3 is None:
                continue
            arguments = [self.convert_args('I', v1), self.convert_args(
                'I', v2), self.convert_args('I', v3)]

            import smafile
            cname = smafile.smali2java(cname)
            json_item = self.get_json_item(cname, mname, arguments)

            mid = json_item['id']
            self.append_json_item(json_item, mtd, old_content, rtn_name)

            if mid in self.results:  # 如果同样的ID存在，那么无需解密
                self.json_list.clear()
                continue

            self.decode(mid)

    def decode(self, mid):
        """解密，并且存放解密结果

        Args:
            mid (str): 指定的解密内容ID

        Returns:
            None
        """
        if not self.json_list or not self.target_contexts:
            return

        jsons = JSONEncoder().encode(self.json_list)

        outputs = {}
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tfile:
            tfile.write(jsons)
        outputs = self.driver.decode(tfile.name)
        os.unlink(tfile.name)

        if not outputs:
            return

        print(outputs)
        self.results[mid] = outputs[mid][0]
        self.json_list.clear()

    def optimize(self):
        """替换解密结果，优化smali代码
        """
        for key, value in self.results.items():
            for mtd, old_content, new_content in self.target_contexts[key]:
                old_body = mtd.get_body()
                new_content = new_content.format(value)
                mtd.set_body(old_body.replace(old_content, new_content))
                self.make_changes = True

        self.smali_files_update()
