import os
import re
import tempfile
from json import JSONEncoder

from colorclass.color import Color
from dexsim import DEBUG_MODE
from dexsim.plugin import Plugin

PLUGIN_CLASS_NAME = "STR_BYTE_STR"

#
# new-instance v0, Ljava/lang/String;
# const-string v1, "aHR0cDcGk……vZmVlZGJhY2s="
# invoke-static {v1}, Lcom/sdk/c/a;->a(Ljava/lang/String;)[B
# move-result-object v1
# invoke-direct {v0, v1}, Ljava/lang/String;-><init>([B)V
#
# =>
#
# 替换为 const-string v0 "解密内容"
# 两步解密
# 1. 使用解密函数解密得到结果byte数组
# 2. 把byte数组转化为字符串


class STR_BYTE_STR(Plugin):
    name = PLUGIN_CLASS_NAME
    enabled = True
    tname = None
    index = 3

    def __init__(self, driver, smalidir):
        Plugin.__init__(self, driver, smalidir)
        self.results = {}   # 存放解密结果

    def run(self):
        if self.ONE_TIME:
            return
        self.ONE_TIME = True
        print('Run ' + __name__, end=' ', flush=True)

        regex = (
            r'new-instance v\d+?, Ljava/lang/String;\s*?'
            r'const-string v\d+?, "([^"]*?)"\s*?'
            r'invoke-static \{v\d+?\}, (.*?;)->(.*?)\(Ljava/lang/String;\)\[B\s*?'
            r'move-result-object v\d+?\s*?'
            r'invoke-direct {(v\d+?), v\d+?}, Ljava/lang/String;-><init>\(\[B\)V\s*?'
        )

        ptn = re.compile(regex, re.MULTILINE)
        for sf in self.smalidir:
            for mtd in sf.get_methods():
                self._process_mtd(mtd, ptn)

        self.optimize()

    def _process_mtd(self, mtd, ptn):
        if DEBUG_MODE:
            print('\n', '+' * 100)
            print('Starting to decode ...')
            print(Color.green(mtd))

        body = mtd.get_body()

        for item in ptn.finditer(body):
            old_content = item.group()  # 匹配到的内容，用来替换
            # arg: 解密参数
            # cname：解密类
            # mname：解密方法
            # rtn_name：最后返回的字符串寄存器，new String的寄存器名字
            arg, cname, mname, rtn_name = item.groups()
            # 转化解密参数
            arguments = [self.convert_args('Ljava/lang/String;', arg)]
            import smafile

            cname = smafile.smali2java(cname)

            json_item = self.get_json_item(cname, mname, arguments)

            mid = json_item['id']
            self.append_json_item(json_item, mtd, old_content, rtn_name)

            if mid in self.results:  # 如果同样的ID存在，那么无需解密
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

        result = bytes(eval(outputs)).decode('utf-8')
        self.results[mid] = result
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
