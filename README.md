# Privacy-Ledger

# 个人记账系统

基于Go语言开发的隐私保护记账系统，采用AES-256加密保护用户数据。

## 功能特性

- 用户注册/登录（密码安全哈希）
- 账目数据加密存储
- 备份文件加密
- 收支统计分析

## 技术栈

- **语言**: Go 1.21+
- **数据库**: SQLite
- **加密**: AES-256-GCM, PBKDF2

## 快速开始

### 安装依赖

```bash
go mod download
```

### 运行项目

```bash
go run main.go
```



## 联系方式

项目：[0901smy/Privacy-Ledger](https://github.com/0901smy/Privacy-Ledger)
作者：0901smy
邮箱：1663321591@qq.com