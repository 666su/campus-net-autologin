@echo off
chcp 65001 >nul
cd /d "%~dp0.."
echo ============================================
echo  校园网断线自动重连 - Windows 一键安装
echo ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [x] 没找到 python。请先安装 Python 3.8+ 并勾选 "Add python.exe to PATH"。
    pause
    exit /b 1
)

if not exist config.json (
    echo [1/3] 首次使用，先生成配置（会问你门户地址、账号、密码）
    copy config.example.json config.json >nul
    python campus_net.py init
) else (
    echo [1/3] 已有 config.json，跳过初始化
)

echo.
echo [2/3] 体检
python campus_net.py doctor

echo.
echo [3/3] 安装后台（开机自启 + 每 5 分钟看护）
python campus_net.py install

echo.
echo 完成。查看状态：python campus_net.py status
pause
