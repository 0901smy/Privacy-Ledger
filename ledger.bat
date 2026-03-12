@echo off
chcp 65001 >nul
cd /d "D:\桌面\Privacy-Ledger"
start http://localhost:8080
start /b go run .
exit
