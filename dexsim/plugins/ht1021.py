import os
import re
import tempfile
from json import JSONEncoder

from colorclass.color import Color
from dexsim import get_value
from dexsim.plugin import Plugin

PLUGIN_CLASS_NAME = "ht1021"

# const-string v0, "FK13406974289BF6"
# goto :goto_16
# :catchall_10
# move-exception v0
# invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;
# move-result-object v0
# throw v0
# :goto_16
# const/4 v1, 0x1
# :try_start_17
# new-array v1, v1, [Ljava/lang/Object;
# const/4 v2, 0x0
# aput-object v0, v1, v2
# const-string v0, "othn.iclauncher"
# invoke-static {v0}, Lothn/filterbutton$SMSBefehle;->bloqueado(Ljava/lang/String;)Ljava/lang/Class;
# move-result-object v0
# const-string v2, "zf"
# const/4 v3, 0x1
# new-array v3, v3, [Ljava/lang/Class;
# const-class v4, Ljava/lang/String;
# const/4 v5, 0x0
# aput-object v4, v3, v5
# invoke-virtual {v0, v2, v3}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
# move-result-object v0
# const/4 v2, 0x0
# invoke-virtual {v0, v2, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
# move-result-object v0
# check-cast v0, Ljava/lang/String;

class ht1021(Plugin):
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
            r'const-string v\d, "(FK[A-Z0-9]+?)"[\s\S]*?'
            r'new-array v\d, v\d, \[Ljava/lang/Object;\s+?'
            r'const/4 v\d, 0x\d+?\s+?'
            r'aput-object v\d, v\d, v\d\s+?'
            r'const-string v\d, "(.*?)"\s+?'
            r'invoke-static {v\d}, Lothn/filterbutton\$SMSBefehle;->bloqueado\(Ljava/lang/String;\)Ljava/lang/Class;\s+?'
            r'move-result-object v\d\s+?'
            r'const-string v\d, "(\w+?)"\s+?'
            r'const/4 v\d, 0x\d\s+?'
            r'new-array v\d, v\d, \[Ljava/lang/Class;\s+?'
            r'const-class v\d, Ljava/lang/String;\s+?'
            r'const/4 v\d, 0x\d\s+?'
            r'aput-object v\d, v\d, v\d\s+?'
            r'invoke-virtual {v\d, v\d, v\d}, Ljava/lang/Class;->getMethod\(Ljava/lang/String;\[Ljava/lang/Class;\)Ljava/lang/reflect/Method;\s+?'
            r'move-result-object v\d\s+?const/4 v\d, 0x\d\s+?'
            r'invoke-virtual {v\d, v\d, v\d}, Ljava/lang/reflect/Method;->invoke\(Ljava/lang/Object;\[Ljava/lang/Object;\)Ljava/lang/Object;\s+?'
            r'move-result-object v\d\s+?'
            r'check-cast (v\d), Ljava/lang/String;\s+?'
            r':try_end_\w+?\s+?'
            r'\.catchall {:try_start_\w+? \.\. :try_end_\w+?} :catchall_\w+?\s'
        )

        ptn = re.compile(regex, re.MULTILINE)
        for sf in self.smalidir:
            for mtd in sf.get_methods():
                self._process_mtd(mtd, ptn)

        self.optimize()

    def _process_mtd(self, mtd, ptn):
        if get_value('DEBUG_MODE'):
            print('\n', '+' * 100)
            print('Starting to decode ...')
            print(Color.green(mtd))

        body = mtd.get_body()

        for item in ptn.finditer(body):
            old_content = item.group()  # 匹配到的内容，用来替换
            arg, cname, mname, rtn_name = item.groups()
            arguments = ['java.lang.String:' + arg]
            json_item = self.get_json_item(cname, mname, arguments)
            mid = json_item['id']
            self.append_json_item(json_item, mtd, old_content, rtn_name)
            if mid in self.results:
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
        self.results[mid] = outputs[mid][0]
        print(outputs)
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
