<div align=center><img src="https://github.com/DeaglePC/XTunnel/blob/master/logos.png"/></div>

[中文](https://github.com/DeaglePC/XTunnel/blob/master/README_CN.md) | [English](https://github.com/DeaglePC/XTunnel/blob/master/README.md)

# 原理
<div align=center><img src="https://github.com/DeaglePC/XTunnel/blob/master/xtun.png" width="400" height="650"/></div>

# XTunnel  
## 简介
用于穿透内网的工具，将局域网的端口暴漏到公网来实现穿透到局域网，类似与frp、ngork之类的软件，但更轻巧，只用于TCP连接，支持多用户多客户端。  

*网络IO模型采用reactor模式的事件驱动模型，实现方法参考redis源码*

**暂时只支持linux，windows下可以用WSL**

## 特点
1. 可执行文件体积小（100+kb）。
2. 运行方便，无需任何依赖环境，可直接以守护进程运行到后台。
3. 配置文件简单，只有三四行即可搞定。
4. 加密传输，经过转发的数据将经过加密再进行传输，加密算法默认采用AES-256-CBC。
5. 高性能IO，基于IO多路复用，网络事件处理参考redis的Reactor的事件驱动模型。

# 安装
* 编译安装  
```bash
git clone https://github.com/DeaglePC/XTunnel.git && cd XTunnel/xtun/ && cmake -DCMAKE_BUILD_TYPE=Release . && make
```
* 下载安装  
[XTunnel_0.2_linux_x86_64.zip](https://github.com/DeaglePC/XTunnel/releases/download/0.2/XTunnel_0.2_linux_x86_64.zip)


# 配置文件

## 服务端
*样例： `ts.ini`*
```ini
[common]
server_port = 10087         # 服务端用于传输控制信息的端口
password = 666              # 服务端认证密码
log_path = /home/xxx/log    # 日志文件保存位置, 请确保有权限读写
```

## 客户端
*样例： `tc.ini`*
```ini
[common]
server_ip = 12.13.14.15     # 服务器的公网ip
server_port = 10087         # 和上面保持一致
password = 666              # 和上面保持一致
log_path = /home/xxx/log    # 日志文件保存位置, 请确保有权限读写

[ssh]
local_ip = 127.0.0.1
local_port = 22             # 本地ssh监听的端口
remote_port = 12300         # 远程服务器暴露的端口

[vnc]
local_ip = 192.168.1.11
local_port = 5900
remote_port = 12301

[rdp]
local_ip = 192.168.1.12
local_port = 3389
remote_port = 12302
```
端口映射情况如下：
|本地局域网地址|公网地址|
|-|-|
|127.0.0.1:22|12.13.14.15:12300|
|192.168.1.11:5900|12.13.14.15:12301|
|192.168.1.12:3389|12.13.14.15:12302|

如上配置文件表示, 通过连接暴漏到公网的IP：端口，就可以连接到局域网内的程序了。比如上面的配置文件将分别可以连接到SSH，VNC，Windows RDP远程桌面。


# 运行（服务端与客户端）
1. 运行服务端（在公网ip的机器上）  
```shell
./xtuns -c ts.ini -d
```
*`-d` 参数表示以守护进程运行*

2. 运行客户端（在局域网机器中运行）
```shell
./xtunc -c tc.ini -d
```

3. 访问公网ip暴露的端口即可访问本地的应用，如ssh
```shell
ssh test@12.13.14.15 -p 12300
```


TODO：  
- [x] 1. 配置文件  
- [x] 2. 密码加密  
- [x] 3. 心跳机制  
- [x] 4. 加密数据  
- [x] 5. 断线重连
- [ ] 6. 只保留n天日志
- [ ] 7. 添加重启和停止参数
- [ ] 8. 优化代码


# 感谢以下开源作者：
[INI](https://github.com/Winnerhust/inifile2)  
[MD5](https://github.com/JieweiWei/md5)    
[LOGGER](https://github.com/ttfutt/logger)
