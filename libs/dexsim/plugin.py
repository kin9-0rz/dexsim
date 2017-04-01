# coding:utf-8
'''
    插件的功能：

    1. 根据正则表达式匹配，需要解密的区域
    2. 将代码区解析为，类、方法、参数
    [{'className':'', 'methodName':'', 'arguments':'', 'id':''}]
    3. 生成json格式，增加区域ID(Hash)

'''

from json import JSONEncoder
import tempfile
import os


class Plugin(object):
    name = 'Plugin'
    description = ''
    version = ''

    CONST_NUMBER = 'const(?:\/\d+) [vp]\d+, (-?0x[a-f\d]+)'
    # ESCAPE_STRING = '''"(.*?)(?<!\\\\)"'''
    ESCAPE_STRING = '''"(.*?)"'''
    CONST_STRING = 'const-string [vp]\d+, ' + ESCAPE_STRING + '.*'
    MOVE_RESULT_OBJECT = 'move-result-object ([vp]\d+)'

    def __init__(self, driver, methods, smali_files):
        self.make_changes = False
        self.driver = driver
        self.methods = methods
        self.smali_files = smali_files

    def run(self):
        '''
            匹配代码，生成指定格式的文件(包含类名、方法、参数)
        '''
        pass

    def optimizations(self, json_list, target_contexts):
        '''
            重复的代码，考虑去除
            生成json
            生成驱动解密
            更新内存
            写入文件
        '''

        if not json_list or not target_contexts:
            return

        jsons = JSONEncoder().encode(json_list)

        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as fp:
            fp.write(jsons)
        outputs = self.driver.decode(fp.name)
        os.unlink(fp.name)

        # 替换内存
        for key in outputs:
            if 'success' in outputs[key]:
                if key not in target_contexts.keys():
                    continue
                for item in target_contexts[key]:
                    old_body = item[0].body
                    target_context = item[1]
                    new_context = item[2] + outputs[key][1]
                    item[0].body = old_body.replace(target_context, new_context)
                    item[0].modified = True
                    self.make_changes = True

        self.smali_files_update()

    def smali_files_update(self):
        '''
            write changes to smali files
        '''
        if self.make_changes:
            for smali_file in self.smali_files:
                smali_file.update()
