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
- **数据库**: SQLite 3.40+
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

然后在浏览器中输入：http://localhost:8080/ 即可访问项目。

### 第二种运行方法

将ledger.bat中的项目文件地址改为文件夹当前在您设备中的地址，然后双击ledger.bat运行。
详细做法：将ledger.bat文件后缀改为txt，然后将这一行：cd /d "D:\桌面\2023102140+孙曼莹+软工课程设计（实验）\Privacy-Ledger"双引号中的文件地址改为您设备中Privacy-Ledger文件夹的实际地址，保存后将txt后缀改回bat即可。双击运行ledger.bat文件即可。

## 联系方式

项目：[0901smy/Privacy-Ledger](https://github.com/0901smy/Privacy-Ledger)
作者：0901smy
邮箱：1663321591@qq.com
