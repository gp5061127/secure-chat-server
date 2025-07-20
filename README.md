# Secure Chat Server

这是 Secure Chat 项目的后端服务端，实现了：

- 用户注册、登录（JWT 验证）
- 基于 WebSocket 的实时消息转发
- SQLite 数据库持久化用户、群组和消息
- 支持端到端加密消息的透明转发（加密逻辑由客户端完成）

## 技术栈

- Golang
- Gorilla WebSocket 和 Mux 路由
- SQLite3 数据库
- bcrypt 密码加密
- JWT 认证

## 快速开始

1. 安装 Go 1.18+ 环境

2. 克隆仓库

```bash
git clone https://github.com/gp5061127/secure-chat-server.git
cd secure-chat-server
```
运行服务

```bash
go run main.go
```
服务默认监听在 :9949 端口

接口说明
POST /api/register
请求体 JSON { "username": "xxx", "password": "xxx" }
注册新用户

POST /api/login
请求体 JSON { "username": "xxx", "password": "xxx" }
登录返回 JWT Token（通过 Cookie 或响应体）

GET /ws
通过 WebSocket 连接，需带 JWT Cookie 认证
实时收发加密消息，服务端透明转发

注意事项
请修改代码中的 jwtKey 为自己的安全密钥

数据库文件 chat.db 会自动创建

本项目仅为示范，生产环境请增加安全和异常处理

许可
MIT License
