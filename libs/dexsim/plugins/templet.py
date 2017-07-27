import re
import os
import yaml

from libs.dexsim.plugin import Plugin

__all__ = ["TEMPLET"]


class TEMPLET(Plugin):
    """Load templets to decode apk/dex."""
    name = "TEMPLET"
    enabled = True
    tname = None

    def __init__(self, driver, methods, smali_files):
        Plugin.__init__(self, driver, methods, smali_files)

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
                    for key, value in item.items():
                        self.tname = key
                        if not value['enabled']:
                            print('Not Load templet:', self.tname)
                            continue
                        print('Load templet:', self.tname)
                        args = value['args'].replace('\\', '')
                        ptn = ''.join(value['pattern'])
                        self.__process(args, ptn)

    def convert_args(self, typ8, value):
        '''Convert the value of register/argument to json format.'''
        if typ8 == 'I':
            return 'I:' + str(value)

        if typ8 == 'Ljava/lang/String;':
            if not isinstance(value, str):
                return None

            import codecs
            item = codecs.getdecoder('unicode_escape')(value)[0]
            args = []
            for i in item.encode("UTF-8"):
                args.append(i)
            return "java.lang.String:" + str(args)

        if typ8 == '[B':
            byte_arr = []
            for item in value:
                if item == '':
                    item = 0
                byte_arr.append(item)
            return '[B:' + str(byte_arr)

        if typ8 == '[C':
            byte_arr = []
            for item in value:
                if item == '':
                    item = 0
                byte_arr.append(item)
            return '[C:' + str(byte_arr)

        print(typ8)

    def init_array_datas(self, body):
        array_datas = {}

        ptn2 = r'(:array_[\w\d]+)\s*.array-data[\w\W\s]+?.end array-data'
        arr_data_prog = re.compile(ptn2)

        for item in arr_data_prog.finditer(body):
            array_data_content = re.split(r'\n\s*', item.group())
            line = 'fill-array-data v0, %s' % item.groups()[0]
            snippet = []
            snippet.append(line)
            snippet.append('return-object v0')
            snippet.extend(array_data_content)
            arr_data = self.emu.call(snippet)
            array_datas[item.groups()[0]] = arr_data

        return array_datas

    def __process(self, args, pattern):
        templet_prog = re.compile(pattern)

        const_ptn = r'const.*?(v\d+),.*'
        const_prog = re.compile(const_ptn)

        file_array_data_ptn = r'fill-array-data (v\d+), (:array_[\d\w]+)'
        file_array_data_prog = re.compile(file_array_data_ptn)

        move_result_obj_ptn = r'move-result-object ([vp]\d+)'
        move_result_obj_prog = re.compile(move_result_obj_ptn)
        type_ptn = r'\[?(I|B|C|Ljava\/lang\/String;)'
        type_prog = re.compile(type_ptn)

        self.json_list.clear()
        self.target_contexts.clear()

        argument_is_arr = False
        if 'arr' in self.tname:
            argument_is_arr = True

        for mtd in self.methods:
            registers = {}
            array_datas = {}

            result = templet_prog.search(mtd.body)
            if not result:
                continue

            if argument_is_arr:
                array_datas = self.init_array_datas(mtd.body)
                if not array_datas:
                    continue

            lines = re.split(r'\n\s*', mtd.body)

            tmp_bodies = lines.copy()

            cls_name = None
            mtd_name = None
            old_content = None

            lidx = -1
            json_item = None
            for line in lines:
                lidx += 1

                result = const_prog.search(line)
                if result:
                    key = result.groups()[0]
                    return_line = 'return-object %s' % key
                    registers[key] = self.emu.call([line, return_line],
                                                   thrown=False)
                    continue

                result = file_array_data_prog.search(line)
                if result:
                    register_name = result.groups()[0]
                    array_data_name = result.groups()[1]
                    if array_data_name in array_datas:
                        registers[register_name] = array_datas[array_data_name]
                    continue

                result_mtd = templet_prog.search(line)
                if not result_mtd:
                    continue

                if 'Ljava/lang/String;->valueOf(I)Ljava/lang/String' in line:
                    continue

                mtd_groups = result_mtd.groups()
                cls_name = mtd_groups[-3][1:].replace('/', '.')
                mtd_name = mtd_groups[-2]
                proto = mtd_groups[-1]

                register_names = []
                #  invoke-static {v14, v16},
                if 'range' not in line:
                    register_names.extend(mtd_groups[0].split(', '))
                elif 'range' in line:
                    # invoke-static/range {v14 .. v16}
                    start, end = re.match(r'v(\d+).*?(\d+)',
                                          mtd_groups[0]).groups()
                    for rindex in range(int(start), int(end) + 1):
                        register_names.append('v' + str(rindex))

                # "arguments": ["I:198", "I:115", "I:26"]}
                arguments = []
                ridx = -1
                for item in type_prog.finditer(proto):
                    ridx += 1
                    arg_type = item.group()

                    rname = register_names[ridx]
                    if rname not in registers:
                        break
                    value = registers[register_names[ridx]]

                    argument = self.convert_args(arg_type, value)
                    if argument is None:
                        break
                    arguments.append(argument)

                    json_item = self.get_json_item(cls_name, mtd_name,
                                                   arguments)
                    # make the line unique, # {id}_{rtn_name}
                    old_content = '# %s' % json_item['id']

                    # If next line is move-result-object, get return
                    # register name.
                    res = move_result_obj_prog.search(lines[lidx + 1])
                    if res:
                        rtn_name = res.groups()[0]
                        # To avoid '# abc_v10' be replace with '# abc_v1'
                        old_content = old_content + '_' + rtn_name + 'X'
                        self.append_json_item(json_item, mtd, old_content,
                                              rtn_name)
                    else:
                        old_content = old_content + '_X'
                        self.append_json_item(json_item, mtd, old_content, None)
                    tmp_bodies[lidx] = old_content

            mtd.body = '\n'.join(tmp_bodies)

        self.optimize()
