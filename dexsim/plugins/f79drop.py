import os
import re
import tempfile
from json import JSONEncoder

from colorclass.color import Color
from dexsim import get_value
from dexsim.plugin import Plugin

PLUGIN_CLASS_NAME = "f79drop"

# 片段1
# base64解密
# new-instance v0, Ljava/lang/String;
# const-string v1, "EZ5LaexoU7OiZuRcijBTc0DJTu7nFWcNOBHfVE0CMIo="
# const/4 v2, 0x2
# base64第二个参数，默认为2
# invoke-static {v1, v2}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B
# move-result-object v1

# 获取密钥，固定的值，程序指定
# iget-object v2, p0, Lujvnd/wx/ogp/ul/c/a$1;->a:Lujvnd/wx/ogp/ul/c/a;
# invoke-static {v2}, Lujvnd/wx/ogp/ul/c/a;->a(Lujvnd/wx/ogp/ul/c/a;)Ljava/lang/String;
# move-result-object v2

# 解密函数
# invoke-static {v1, v2}, Lujvnd/wx/ogp/ul/a/a;->a([BLjava/lang/String;)[B
# move-result-object v1

# byte数组转字符串
# invoke-direct {v0, v1}, Ljava/lang/String;-><init>([B)V

# 片段2
# new-instance v1, Ljava/lang/String;
# const-string v2, "ZnMakLDpgn4MNg1rY1CyWg==" 第二个参数默认为2
# invoke-static {v2, v8}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B
# move-result-object v2

# iget-object v3, p0, Lujvnd/wx/ogp/ul/c/b;->a:Lujvnd/wx/ogp/ul/c/a;
# invoke-static {v3}, Lujvnd/wx/ogp/ul/c/a;->a(Lujvnd/wx/ogp/ul/c/a;)Ljava/lang/String;
# move-result-object v3

# invoke-static {v2, v3}, Lujvnd/wx/ogp/ul/a/a;->a([BLjava/lang/String;)[B
# move-result-object v2

# invoke-direct {v1, v2}, Ljava/lang/String;-><init>([B)V


class f79drop(Plugin):
    name = PLUGIN_CLASS_NAME
    enabled = False
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
            r'const-string v\d+?, "([^"]*?)"\s*?'
            r'invoke-static \{v\d\}, (.*?;)->(.*?)\(Ljava/lang/Object;\)Ljava/lang/String;\s*'
            r'move-result-object (v\d+?)\s*?'
        )

        ptn = re.compile(regex, re.MULTILINE)
        for sf in self.smalidir:
            for mtd in sf.get_methods():
                self._process_mtd(mtd, ptn)

        self.optimize()

    def _process_mtd(self, mtd, ptn):
        body = mtd.get_body()

        for item in ptn.finditer(body):
            old_content = item.group()  # 匹配到的内容，用来替换
            # base解密的字符串，base64解密
            # 得到结果再次解密，
            # rtn_name：最后返回的字符串寄存器，new String的寄存器名字
            arg, cname, mname, rtn_name = item.groups()
            print(old_content)
            print(item.groups())
            arguments = ['java.lang.Object:' + arg]

            import smafile
            cname = smafile.smali2java(cname)
            print(cname, mname, arguments)
            json_item = self.get_json_item(cname, mname, arguments)
            mid = json_item['id']
            self.append_json_item(json_item, mtd, old_content, rtn_name)
            if mid in self.results:
                self.json_list.clear()
                continue
            self.decode(mid)
            raise A

    def decode_s(self, s):
        length = len(s)
        chars = [0 for i in range(length)]
        print(chars)
        index = length - 1
        while index >= 0:
            print(s[index], ord(s[index]), chr(ord(s[index]) ^ 25))
            idx = index - 1
            chars[index] = chr(ord(s[index]) ^ 25)
            print()
            if idx < 0:
                break
            index = idx - 1
            chars[idx] = chr(ord(s[idx]) ^ 0x76)
            print(s[idx], ord(s[idx]), chr(ord(s[idx]) ^ 0x76))

        return chars

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
        self.results[mid] = outputs
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
