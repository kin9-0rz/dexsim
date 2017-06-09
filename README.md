# dexsim

A pattern based Dalvik deobfuscator which uses limited execution to improve semantic analysis

Original idea inspired from Caleb Fenton 's [dex-oracle](https://github.com/CalebFenton/dex-oracle).

It's a PY3 version for [dex-oracle](https://github.com/CalebFenton/dex-oracle).



### Installation

#### 1. Install [Smali](https://github.com/JesusFreke/smali)

You can download smali from [here](https://bitbucket.org/JesusFreke/smali/downloads/):

```
https://bitbucket.org/JesusFreke/smali/downloads/smali-2.2.1.jar
https://bitbucket.org/JesusFreke/smali/downloads/baksmali-2.2.1.jar
https://bitbucket.org/JesusFreke/smali/downloads/smali
https://bitbucket.org/JesusFreke/smali/downloads/baksmali
```



For Win, maybe you need two bat files:

**smali.bat**

```visual basic
@echo off
java -jar %~dp0smali.jar %*
```

**baksmali.bat**
```visual basic
@echo off
java -jar %~dp0baksmali.jar %*
```



Make sure `smali` and `baksmali` on your path.



#### 2. Install Android SDK / ADB

Make sure `adb` is on your path.



#### 3. Install the requirements

```
pip install -r requirements.txt
```



#### 4. Connect a Device or Emulator

*You must have either an emulator running or a device plugged in for dexsim to work.*

Dexsim needs to execute methods on an live Android system. This can either be on a device or an emulator. If it's a device, *make sure you don't mind running potentially hostile code on it*.



### Usage

```shell
usage: dexsim [-h] [-i I] [-o O] f

positional arguments:
  f           Smali Directory / DEX / APK

optional arguments:
  -h, --help  show this help message and exit
  -i I        Only optimize methods and classes matching the pattern, e.g.
              La/b/c;->decode
  -o O        output file path
```

For example, to only deobfuscate methods in a class called `com/a/b;` , inside of an APK called 'test.apk':

```
dexsim test.apk -i com/a/b;
```



### Support

- [x] Ljava/lang/String;->\<init>([B)V
- [x] func(Ljava/lang/String;)Ljava/lang/String;
- [x] func(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
- [x] func(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
- [x] func(I)Ljava/lang/String;
- [x] func(II)Ljava/lang/String;
- [x] func(III)Ljava/lang/String;
- [x] func([B)Ljava/lang/String;
- [x] func([I)Ljava/lang/String;
- [x] Replace Variable : I
- [x] Replace Variable : Ljava/lang/String;
- [ ] Replace Variable : [B
- [ ] fun(Ljava/lang/String;)[B




### Plugins

They are in `libs/dexsim/plugins`, you can write plugin by yourself.