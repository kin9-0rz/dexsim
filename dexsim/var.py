import re


is_debug = False

INT = 'int'

# 定义常见的正则
# 匹配proto
PROTO_RE = (
    r'(B|S|C|I|J|F|D|Ljava/lang/String;|'
    r'\[B|\[S|\[C|\[I|\[J|\[F|\[D|\[Ljava/lang/String;)'
)

ARRAY_DATA_PATTERN = r':array_[\w\d]+\s*.array-data[\w\W\s]+.end array-data'

proto_ptn = re.compile(PROTO_RE)
arr_data_prog = re.compile(ARRAY_DATA_PATTERN)