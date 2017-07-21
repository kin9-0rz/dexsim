# coding:utf-8

import hashlib
from json import JSONEncoder
import re
import os
import yaml

from libs.dexsim.plugin import Plugin


__all__ = ["TEMPLET"]


class TEMPLET(Plugin):

    name = "TEMPLET"
    desc = '通过加载模板，自动解密'
    enabled = True
    tname = None

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)
        from smaliemu.emulator import Emulator
        self.emu = Emulator()

    def run(self):
        print('run Plugin: %s' % self.name, end=' -> ')
        self.__load_templets()

    def __load_templets(self):
        print()
        templets_path = os.path.dirname(__file__)[:-7] + 'templets'
        for filename in os.listdir(templets_path):
            file_path = os.path.join(templets_path, filename)
            with open(file_path, encoding='utf-8') as f:
                datas = yaml.load(f.read())
                for item in datas:
                    for key in item:
                        self.tname = key

                        if not item[key]['enabled']:
                            print('Not Load templet:', self.tname)
                            continue
                        print('Load templet:', self.tname)
                        args = item[key]['args'].replace('\\', '')
                        ptn = ''.join(item[key]['pattern'])
                        self.__process(args, ptn)

    def convert_args(self, typ8, value):
        '''
            根据参数类型和值，将其转换为json格式
        '''
        if typ8 == 'I':
            return 'I:' + str(value)

        if typ8 == 'Ljava/lang/String;':
            import codecs
            try:
                item = codecs.getdecoder('unicode_escape')(value)[0]
            except:
                raise Exception

            args = []
            for i in item.encode("UTF-8"):
                args.append(i)
            return "java.lang.String:" + str(args)

    def __process(self, args, pattern):
        templet_prog = re.compile(pattern)
        print(pattern)

        v_prog = re.compile(r'(v\d+),')
        # const_ptn = r'const/\d+ (v\d+), (0x[\d\w]*)t?'
        const_ptn = r'const.*?(v\d+),.*'

        const_prog = re.compile(const_ptn)
        move_result_obj_ptn = r'move-result-object ([vp]\d+)'
        move_result_obj_prog = re.compile(move_result_obj_ptn)
        type_ptn = r'\[?(I|B|Ljava\/lang\/String;)'
        type_prog = re.compile(type_ptn)

        # 判断是否已获得解密函数的类名、方法
        flag = False
        # 存放解密对象
        self.json_list = []
        self.target_contexts = {}

        for mtd in self.methods:
            register = {}

            result = templet_prog.search(mtd.body)
            if not result:
                continue

            lines = re.split(r'\n\s*', mtd.body)

            tmp_bodies = lines.copy()

            cls_name = None
            mtd_name = None
            arguments = []
            old_content = None
            old_content_bak = None

            line_number = 0
            counter = -1
            json_item = None
            for line in lines:
                counter += 1
                # 如果已获取解密类名、方法、参数
                if flag:
                    # 尝试获取返回存放的寄存器，如果没有则
                    res = move_result_obj_prog.search(line)
                    # print(res, line)
                    if res:
                        # print(res)
                        rtn_name = res.groups()[0]
                        self.append_json_item(json_item, mtd, old_content, rtn_name)
                        flag = False
                        arguments = []
                        cls_name = None
                        mtd_name = None
                        continue
                    else:
                        # 如果没有返回值的情况，则默认替换打印数据
                        self.append_json_item(json_item, mtd, old_content, None)

                        flag = False
                        arguments = []
                        cls_name = None
                        mtd_name = None
                        pass

                # 判断其是否有返回值
                result = const_prog.search(line)
                if result:
                    key = result.groups()[0]
                    return_line = 'return-object %s' % key
                    register[key] = self.emu.call([line, return_line], thrown=False)
                    continue

                # 匹配解密模板
                result_mtd = templet_prog.search(line)
                if not result_mtd:
                    continue

                cls_name = result_mtd.groups()[-3][1:].replace('/', '.')
                mtd_name = result_mtd.groups()[-2]
                proto = result_mtd.groups()[-1]

                # 生成arguments
                # "arguments": ["I:198", "I:115", "I:26"]}

                count = 0
                for i in type_prog.finditer(proto):
                    arg_type = i.group()
                    try:
                        value = register[result_mtd.groups()[count]]
                        try:
                            arguments.append(self.convert_args(arg_type, value))
                            json_item = self.get_json_item(cls_name, mtd_name, arguments)
                            count += 1
                            line_number = counter

                            # 使目标替换位置变得唯一，保证替换的唯一性
                            #（同样的解密方法、参数，拥有一样的ID）
                            # 仅仅是内存里面的修改，如果解密失败的情况，内存中的内容不会写入文件
                            # NOTE 仍然不可能避免，同一个方法，一处解密成功，外一处解密失败，
                            # 导致写入文件的情况
                            old_content = '# %s' % json_item['id']
                            tmp_bodies[line_number] = old_content
                        except:
                            # TODO 可能需要处理
                            print('-' * 80)
                            print('ERROR：参数转换异常')
                            print(mtd.descriptor)
                            print(result_mtd.groups())
                            print(register)
                            print('-' * 80)
                            break
                    except KeyError:
                        arguments = []
                        break

                if arguments:
                    flag = True
                else:
                    continue

            mtd.body = '\n'.join(tmp_bodies)

        self.optimize()
