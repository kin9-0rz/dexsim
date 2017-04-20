# dexsim

这是一个 Python3 版本的 [dex-oracle](https://github.com/CalebFenton/dex-oracle)，技术原理详细请看 [dex-oracle](https://github.com/CalebFenton/dex-oracle)。

### 安装

1. [smali](https://github.com/JesusFreke/smali) - 请用最新版
2. adb
3. pip install -r requirements.txt

注意：请确认命令行下能运行这些命令：baksmali，smali, adb, java。

### 用法

1. 连接到Android模拟器或者手机
2. 执行命令`dexsim smali_dir/dex/apk`

### 支持解密方法
- [x] Ljava/lang/String;->\<init>([B)V
- [x] func(Ljava/lang/String;)Ljava/lang/String;
- [x] func(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
- [x] func(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
- [x] func(I)Ljava/lang/String;
- [x] func(II)Ljava/lang/String;
- [x] func(III)Ljava/lang/String;
- [x] func([B)Ljava/lang/String;
- [x] Replace Variable : I
- [x] Replace Variable : Ljava/lang/String;
- [ ] Replace Variable : [B
- [ ] fun(Ljava/lang/String;)[B


### 解密插件

支持插件编写。插件目录在`libs/dexsim/plugins`下，具体请参考现有解密插件代码。
