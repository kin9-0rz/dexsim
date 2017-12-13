# DSS(dexsim-server)

dexsim 的 Android服务端，通过动态加载的方式，为 dexsim 提供解密服务。

## 为什么
1. 模拟执行smali代码时，寄存器中的值，不能保证完全正确，有可能解密出现乱码，而且还存在效率问题。
2. 静态解密，遇到Context等于Android紧密相关的类就无法处理，而且会有未知的无法处理的情况。
3. 非静态解密，不好处理，特别是与Context有关的情况。
4. Native 解密的时候，发现有需要Context的情况。

基于以上原因，需要一个能够获取Context，并且能加载目标APK的APP，这就是dexsim-server。


## TODO
- [x] Intent - 利用`adb shell am broadcast` - 接受来自dexsim的命令
- [x] 动态加载 - 需要选一个合适的插件框架 - 待调研
- [ ] 解密处理部分 - 在原有的基础上修改，不做大的变化
