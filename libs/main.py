import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from time import clock

from cigam import Magic

from .dexsim import logs
from .dexsim.driver import Driver
from .dexsim.oracle import Oracle

main_path = ''
for path in sys.path:
    if path != '' and path in __file__:
        main_path = path

with open(os.path.join(main_path, "res", 'smali.txt'), encoding='utf-8') as f:
    lines = f.readlines()


def clean(smali_dir):
    for line in lines:
        clz = line.split('#')[0]
        xpath = smali_dir + os.sep + clz.replace('.', os.sep).strip('\n')
        if os.path.exists(xpath):
            shutil.rmtree(xpath)


def dexsim(dex_file, smali_dir, include_str):
    driver = Driver()
    driver.install(dex_file)

    oracle = Oracle(smali_dir, driver, include_str)
    oracle.divine()


def baksmali(dex_file, output_dir='out'):
    '''
    dex to smali
    '''
    cmd = 'baksmali d %s -o %s' % (dex_file, output_dir)
    subprocess.call(cmd, shell=True)
    clean(output_dir)

    return output_dir


def smali(smali_dir, output_file='out.dex'):
    '''
    smali to dex
    '''
    cmd = 'smali a %s -o %s' % (smali_dir, output_file)
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
    if os.path.isdir(args.f):  # smali dir
        if args.f.endswith('\\') or args.f.endswith('/'):
            smali_dir = args.f[:-1]
        else:
            smali_dir = args.f
        dex_file = smali(smali_dir, os.path.basename(smali_dir) + '.dex')
        dexsim_dex(dex_file, smali_dir, include_str, output_dex)
    elif Magic(args.f).get_type() == 'apk':
        apk_path = args.f

        if logs.DEBUG:
            tempdir = os.path.join(os.path.abspath(os.curdir), 'clztmp')
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

        smali(smali_dir, dex_file)
        dexsim_dex(dex_file, smali_dir, include_str, output_dex)
        if not logs.DEBUG:
            shutil.rmtree(tempdir)
    else:
        dex_file = os.path.basename(args.f)
        baksmali(dex_file, smali_dir)
        dexsim_dex(dex_file, smali_dir, include_str, output_dex)


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
