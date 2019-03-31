# XTunnel  
用于穿透内网的工具，基于端口映射原理，正式版本，支持多用户多客户端  
io模型采用reactor模式的事件驱动模型，实现方法参考redis源码

## 如何使用  
1. 编译代码  
```shell
make clean
make
cd bin
```
在公网服务器上运行服务端  
在本地运行客户端，填好配置文件  
例如：把本地22端口暴露到公网38438端口  

2. 填服务器配置文件  
*在执行的时候用-c参数指定配置文件路径，这里是 /home/ts.ini*
```ini
[common]
server_port = 10086 # 服务端用于传输控制信息的端口
proxy_port = 10001  # 服务端用于穿数据的端口
password = 666      # 服务端认证密码
log_path = /home/log # 日志文件保存位置, 请确保有权限读
```
3. 填客户端配置文件  
*在执行的时候用-c参数指定配置文件路径，这里是 /home/tc.ini*
```ini
[common]
server_ip = 1.1.1.1   # 服务器的公网ip
server_port = 10086   # 和上面保持一致
proxy_port = 10001    # 和上面保持一致
password = 666        # 和上面保持一致
log_path = /home/log # 日志文件保存位置, 请确保有权限读写

[ssh]
local_ip = 127.0.0.1
local_port = 22     # 本地ssh监听的端口
remote_port = 38438 # 远程服务器暴露的端口
```

4. 运行服务端  
```shell
cd bin
./tunserver -c /home/ts.ini -d
```

5. 运行客户端
```shell
cd bin
./tunclient -c /home/tc.ini -d
```

6. 访问公网ip暴露的端口即可访问本地的ssh
```shell
ssh test@1.1.1.1 -p 38438
```

TODO：  
- [x] 1.配置文件  
- [x] 2.密码加密  
- [x] 3.心跳机制  
- [ ] 4.ssl通讯  


## 感谢以下开源作者：
ini文件解析来自：https://github.com/Winnerhust/inifile2  
md5加密来自：https://github.com/JieweiWei/md5  
logger来自：https://github.com/ttfutt/logger