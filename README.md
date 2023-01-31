# Clash规则

## 文件介绍
'irectGame.yaml ---------------- 能够直连的游戏域名
'Lite_Proxy.yaml ---------------- 自定义的需要被代理的域名
ProxyGame.yaml  ---------------- 需要被代理的游戏域名（包括游戏平台的连接）
clash-parse.py  ---------------- 自动转换订阅的python脚本，能整合多个机场订阅，并自动识别不同国家并分类，最后保存为config1.yaml
clash-parse.yaml---------------- 配合clash-parse.py使用，作为订阅转换的基础
local.yaml      ---------------- 配合clash-parse.py使用，自定义本地的tun和dns设置，订阅连接填入sub字段
config.yaml     ---------------- 使用最新的proxy-provider字段的配置，从config1.yaml读取节点数据
highload.yaml   ---------------- 能够直连的国外网盘域名
