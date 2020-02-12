<div align=center><img src="https://github.com/DeaglePC/XTunnel/blob/master/logos.png"/></div>

# XTunnel  
用于穿透内网的工具，基于端口映射原理，正式版本，支持多用户多客户端  
io模型采用reactor模式的事件驱动模型，实现方法参考redis源码

**暂时只支持linux，windows下可以用WSL**

## 安装
* 编译安装  
```bash
git clone https://github.com/DeaglePC/XTunnel.git && cd XTunnel/xtun/ && cmake -DCMAKE_BUILD_TYPE=Release . && make
```
* OR 下载安装  
[点我下载](https://github.com/DeaglePC/XTunnel/releases/download/0.2/XTunnel_0.2_linux_x86_64.zip)


## 编辑配置文件

### 服务端
*样例： `ts.ini`*
```ini
[common]
server_port = 10087         # 服务端用于传输控制信息的端口
password = 666              # 服务端认证密码
log_path = /home/xxx/log    # 日志文件保存位置, 请确保有权限读写
```

### 客户端
*样例： `tc.ini`*
```ini
[common]
server_ip = 12.13.14.15       # 服务器的公网ip
server_port = 10087         # 和上面保持一致
password = 666              # 和上面保持一致
log_path = /home/xxx/log    # 日志文件保存位置, 请确保有权限读写

[ssh]
local_ip = 127.0.0.1
local_port = 22             # 本地ssh监听的端口
remote_port = 38439         # 远程服务器暴露的端口

[nc]
local_ip = 127.0.0.1
local_port = 6666
remote_port = 38438
```
如上配置文件表示：客户端将本地 `127.0.0.1:22` 以及 `127.0.0.1:6666` 分别映射到公网的 `12.13.14.15:38439` 和 `12.13.14.15:38438`, 直接连接公网的地址即可连接到本地局域网的应用上  


## 运行服务端与客户端
1. 运行服务端（在公网ip的机器上）  
```shell
./tunserver -c ts.ini -d
```
*`-d` 参数表示以守护进程运行*

2. 运行客户端（在局域网机器中运行）
```shell
./tunclient -c tc.ini -d
```

3. 访问公网ip暴露的端口即可访问本地的应用，如ssh
```shell
ssh test@12.13.14.15 -p 38439
```

TODO：  
- [x] 1.配置文件  
- [x] 2.密码加密  
- [x] 3.心跳机制  
- [x] 4.加密数据  
- [x] 5.断线重连


## 感谢以下开源作者：
[ini](https://github.com/Winnerhust/inifile2)  
[MD5](https://github.com/JieweiWei/md5)    
[LOGGER](https://github.com/ttfutt/logger)
