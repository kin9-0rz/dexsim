# dexsim

利用APK动态加载解密，旧逻辑在old分支。


## 安装

- baksmali - 用于把apk／dex文件反编译为smali
- adb - 用于push文件到手机／模拟器
- 安装依赖 - `pip install -r requirements.txt`
- 安装服务端 - `adb install server/dss.apk`

## 用法

1. 连接一台模拟器或手机（Root）
2. 保证 `chmod 777 /data/local/`
2. 至少启动dss应用一次（没有启动过的APP接收不到广播）
3. 执行 `dexsim apk/dex`
