from pyadb3 import ADB
import argparse
import os
import re
import shutil
import subprocess
import tempfile
import time
import zipfile

from cigam import Magic

from dexsim import logs, var
from dexsim.driver import Driver
from dexsim.oracle import Oracle

main_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
JAVA = 'java'

with open(os.path.join(main_path, 'datas', 'filters.txt')) as f:
    lines = f.read().splitlines()


adb = ADB()
PLUGIN_PATH = '/data/local/tmp/plugins/'


def clean(smali_dir):
    for line in lines:
        clz = line.split('#')[0]
        xpath = smali_dir + os.sep + clz.replace('.', os.sep).strip('\n')
        if os.path.exists(xpath):
            shutil.rmtree(xpath)


def push_apk_to_device(apk_path):
    adb.run_shell_cmd(['mkdir', PLUGIN_PATH])
    adb.run_cmd(['push', apk_path, PLUGIN_PATH])
    adb.run_shell_cmd(
        ['am', 'start', '-n', 'mikusjelly.zerolib/mikusjelly.zero.MainActivity'])
    adb.run_cmd(['forward', 'tcp:8888', 'tcp:9999'])


def rm_device_file():
    # 停止进程
    adb.run_shell_cmd(['am', 'force-stop', 'mikusjelly.zerolib'])  # 停止进程
    adb.run_cmd(['forward', '--remove-all'])
    adb.run_shell_cmd(['rm', '-rf', PLUGIN_PATH])


def dexsim(dex_file, smali_dir, includes):
    """执行解密

    Args:
        dex_file ([type]): [description]
        smali_dir ([type]): [description]
        includes ([type]): [description]
    """
    push_apk_to_device(dex_file)

    driver = Driver()
    oracle = Oracle(smali_dir, driver, includes)
    oracle.divine()

    rm_device_file()


def baksmali(dex_file, output_dir='out'):
    '''
    dex to smali
    '''
    baksmali_path = os.path.join(main_path, 'smali', 'baksmali.jar')
    cmd = '{} -jar {} d {} -o {}'.format(JAVA,
                                         baksmali_path, dex_file, output_dir)
    subprocess.call(cmd, shell=True)
    clean(output_dir)

    return output_dir


def smali(smali_dir, output_file='out.dex'):
    """smali to dex

    Args:
        smali_dir (str): smali fold
        output_file (str, optional): output filename

    Returns:
        [type]: [description]
    """
    smali_path = os.path.join(main_path, 'smali', 'smali.jar')
    cmd = '{} -jar {} a {} -o {}'.format(JAVA,
                                         smali_path, smali_dir, output_file)
    subprocess.call(cmd, shell=True)

    return output_file


def main(args):
    logs.isdebuggable = args.d
    var.is_debug = args.d
    includes = args.includes

    smali_dir = None
    if logs.isdebuggable:
        smali_dir = os.path.join(os.path.abspath(os.curdir), 'smali')
    else:
        smali_dir = tempfile.mkdtemp()

    output_dex = None
    if args.o:
        output_dex = args.o

    dex_file = None
    # smali dir
    if os.path.isdir(args.f):
        if args.f.endswith('\\') or args.f.endswith('/'):
            smali_dir = args.f[:-1]
        else:
            smali_dir = args.f
        dex_file = smali(smali_dir, os.path.basename(smali_dir) + '.dex')
        dexsim_dex(dex_file, smali_dir, includes, output_dex)
    elif Magic(args.f).get_type() == 'apk':
        apk_path = args.f

        if logs.isdebuggable:
            tempdir = os.path.join(os.path.abspath(os.curdir), 'tmp_dir')
            if not os.path.exists(tempdir):
                os.mkdir(tempdir)
        else:
            tempdir = tempfile.mkdtemp()

        ptn = re.compile(r'classes\d*.dex')

        zipFile = zipfile.ZipFile(apk_path)
        for item in zipFile.namelist():
            if ptn.match(item):
                output_path = zipFile.extract(item, tempdir)
                baksmali(output_path, smali_dir)
        zipFile.close()

        dex_file = os.path.join(tempdir, 'new.dex')

        # smali(smali_dir, dex_file)
        dexsim_dex(args.f, smali_dir, includes, output_dex)
        if not logs.isdebuggable:
            shutil.rmtree(tempdir)
    elif Magic(args.f).get_type() == 'dex':
        dex_file = os.path.basename(args.f)
        baksmali(dex_file, smali_dir)
        dexsim_dex(dex_file, smali_dir, includes, output_dex)
    else:
        print("Please give smali_dir/dex/apk.")


def dexsim_dex(dex_file, smali_dir, includes, output_dex):
    dexsim(dex_file, smali_dir, includes)
    if output_dex:
        smali(smali_dir, output_dex)
    else:
        smali(smali_dir,
              os.path.splitext(os.path.basename(dex_file))[0] + '.sim.dex')

    if not logs.isdebuggable:
        shutil.rmtree(smali_dir)

# 通过python3 setup安装
# 使用默认插件解密。（指定特定的插件名解密 methdo(I)LObject/lang/String;）
# 可以手工指定解密的插件。
# 自动模式
# 将自动加载目录下所有的插件
# 指定特定的插件


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='dexsim', description='')
    parser.add_argument('f', help='Smali Directory / DEX / APK')
    parser.add_argument('-i', '--includes', nargs='*',
                        help='仅仅处理smali路径包含该路径的文件')
    parser.add_argument('-o', help='output file path')
    parser.add_argument('-d', action='store_true',
                        help='logs.isdebuggable MODE')

    args = parser.parse_args()

    start = time.time()
    main(args)
    finish = time.time()
    print('\n%fs' % (finish - start))
