# dexsim

利用APK动态加载解密，旧逻辑在old分支。


## 安装

- baksmali - 用于把apk／dex文件反编译为smali
- adb - 用于push文件到手机／模拟器
- 安装依赖 - `pip install -r requirements.txt`
- 安装服务端 - `adb install -t server/dss.apk`

## 用法

1. 连接一台模拟器或手机
2. 创建数据目录
  ```
  $ adb shell
  $ su
  # cd /data/local
  # mkdir dss dss_data
  # ll
  drwxrwxrwx root     root              2018-02-05 15:22 dss
  drwxrwxrwx root     root              2018-02-05 15:22 dss_data
  drwxrwx--x shell    shell             2018-02-05 15:13 tmp
  ```
4. 至少启动dss应用一次（没有启动过的APP可能接收不到广播）
5. 执行 `dexsim apk`

## 其他说明

具体想法在Doc.md中。

样本则在dexsim-samples项目中备份。