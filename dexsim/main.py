import argparse
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from time import clock

from cigam import Magic

from . import logs
from .driver import Driver
from .oracle import Oracle

main_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
JAVA = 'java'

with open(os.path.join(main_path, 'datas', 'filters.txt')) as f:
    lines = f.read().splitlines()


def clean(smali_dir):
    for line in lines:
        clz = line.split('#')[0]
        xpath = smali_dir + os.sep + clz.replace('.', os.sep).strip('\n')
        if os.path.exists(xpath):
            shutil.rmtree(xpath)


def dexsim(dex_file, smali_dir, include_str):
    driver = Driver()
    driver.push_to_dss(dex_file)

    oracle = Oracle(smali_dir, driver, include_str)
    oracle.divine()


def baksmali(dex_file, output_dir='out'):
    '''
    dex to smali
    '''
    baksmali_path = os.path.join(main_path, 'smali', 'baksmali.jar')
    cmd = '{} -jar {} d {} -o {}'.format(JAVA,
                                         baksmali_path, dex_file, output_dir)
    print(cmd)
    subprocess.call(cmd, shell=True)
    clean(output_dir)

    return output_dir


def smali(smali_dir, output_file='out.dex'):
    '''
    smali to dex
    '''
    smali_path = os.path.join(main_path, 'smali', 'smali.jar')
    cmd = '{} -jar {} a {} -o {}'.format(JAVA,
                                         smali_path, smali_dir, output_file)
    subprocess.call(cmd, shell=True)

    return output_file


def main(args):
    include_str = args.i

    # Debug mode
    logs.DEBUG = args.d
    # logs.DEBUG = DEBUG
    smali_dir = None
    if logs.DEBUG:
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
        dexsim_dex(dex_file, smali_dir, include_str, output_dex)
    elif Magic(args.f).get_type() == 'apk':
        apk_path = args.f

        if logs.DEBUG:
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
        dexsim_dex(args.f, smali_dir, include_str, output_dex)
        if not logs.DEBUG:
            shutil.rmtree(tempdir)
    elif Magic(args.f).get_type() == 'dex':
        dex_file = os.path.basename(args.f)
        baksmali(dex_file, smali_dir)
        dexsim_dex(dex_file, smali_dir, include_str, output_dex)
    else:
        print("Please give smali_dir/dex/apk.")


def dexsim_dex(dex_file, smali_dir, include_str, output_dex):
    dexsim(dex_file, smali_dir, include_str)
    if output_dex:
        smali(smali_dir, output_dex)
    else:
        smali(smali_dir,
              os.path.splitext(os.path.basename(dex_file))[0] + '.sim.dex')

    if not logs.DEBUG:
        shutil.rmtree(smali_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='dexsim', description='')
    parser.add_argument('f', help='Smali Directory / DEX / APK')
    parser.add_argument('-i',
                        help='Only optimize methods and\
                        classes matching the pattern, e.g. La/b/c;->decode')
    parser.add_argument('-o', help='output file path')
    parser.add_argument('-d', action='store_true', help='DEBUG MODE')

    args = parser.parse_args()

    start = clock()
    main(args)
    finish = clock()
    print('\n%fs' % (finish - start))
