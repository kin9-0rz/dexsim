import re


class SmaliFile:

    accessor_regex = '(interface|public|protected|private|abstract|static|final|synchronized|transient|volatile|native|strictfp|synthetic|enum|annotation|bridge| |)+'

    def __init__(self, file_path):
        self.file_path = file_path
        self.modified = False

        self.class_name = None
        self.super = None
        self.interfaces = []
        self.methods = []
        self.fields = []
        self.content = None

        self._parse(file_path)

    def _parse(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            self.content = f.read()

        class_regex = '\.class%s (L[^;]+;)' % self.accessor_regex
        p = re.compile(class_regex)
        try:
            line = p.search(self.content).group()
        except AttributeError:
            print(self.content)
        idx = line.rindex(' ')
        self.class_name = line[idx + 1:]

        super_regex = '\.super (L[^;]+;)'
        p = re.compile(super_regex)
        line = p.search(self.content).group()
        self.super = line[7:]

        interfaces_regex = '\.implements (L[^;]+;)'
        p = re.compile(interfaces_regex)
        for i in p.finditer(self.content):
            self.interfaces.append(i.group().replace('.implements ', ''))

        field_regex = '\.field %s [^\s]+' % self.accessor_regex
        p = re.compile(field_regex)
        for i in p.finditer(self.content):
            line = i.group()
            idx = line.rindex(' ')
            self.fields.append(SmaliField(self.class_name, line[idx + 1:]))

        method_regex = '\.method [%s\s-]+ [^\s]+' % self.accessor_regex
        p = re.compile(method_regex)
        for i in p.finditer(self.content):
            line = i.group()
            idx = line.rindex(' ')
            method_signature = line[idx + 1:]

            escape_line = re.escape(line)
            method_body_regex = '%s((?!\.end method)[.\s\S])*.end method' % escape_line
            p2 = re.compile(method_body_regex)
            result = p2.search(self.content).group()
            body = result.replace(line, '').replace('.end method', '')
            self.methods.append(
                SmaliMethod(
                    self.class_name,
                    method_signature,
                    body))

    def build_method_regex(self, mtd_sign):
        return '\.method [%s\s-]+%s((?!\.end method)[.\s\S])*.end method' % (self.accessor_regex, re.escape(mtd_sign))

    def update(self):
        '''
            update smali file.
        '''
        for mtd in self.methods:
            if mtd.modified:
                self.update_method(mtd)
                mtd.modified = False

        with open(self.file_path, 'w', encoding='utf-8') as f:
            f.write(self.content)

    def update_method(self, mtd):
        body_reg = self.build_method_regex(mtd.signature)
        p2 = re.compile(body_reg)
        result = p2.search(self.content).group()
        start = result.index('\n')
        old_body = result[start:-11]
        if old_body in self.content:
            self.content = self.content.replace(old_body, mtd.body)


class SmaliField:

    def __init__(self, class_name, field_signature):
        self.class_name = class_name
        self.descriptor = class_name + '->' + field_signature
        self.name, self.type = field_signature.split(':')

    def to_str(self):
        return descriptor


class SmaliMethod:

    def __init__(self, class_name, signature, body=None):
        self.modified = False
        self.class_name = class_name
        l_bracket_idx = signature.index('(')
        self.name = signature[:signature.index('(')]
        self.body = body
        r_bracket_idx = signature.index(')')
        self.return_type = signature[r_bracket_idx + 1:]
        self.descriptor = class_name + '->' + signature
        self.signature = signature

        self.parameters = []
        PARAMETER_ISOLATOR = '\([^\)]+\)'
        PARAMETER_INDIVIDUATOR = '(\[*(?:[BCDFIJSZ]|L[^;]+;))'
        pattern1 = re.compile(PARAMETER_ISOLATOR)
        mth = pattern1.search(signature[l_bracket_idx:r_bracket_idx + 1])
        if mth:
            pattern2 = re.compile(PARAMETER_INDIVIDUATOR)
            for item in pattern2.finditer(
                    signature[l_bracket_idx:r_bracket_idx + 1]):
                self.parameters.append(item.group())

    def to_str(self):
        return self.descriptor
