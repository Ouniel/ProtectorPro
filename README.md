# ProtectorPro

[![Go Version](https://img.shields.io/badge/Go-1.20+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-green.svg)](README.md)

一个强大的系统安全评估工具，基于 Go 语言开发，支持 Windows 和 Linux 平台，专注于深度的系统安全分析和风险评估。
## 🔍 主要功能

### 1. 安全事件分析
- 支持多种事件源的收集和分析：
  - Windows 安全事件日志
  - Linux 系统日志
  - 应用程序日志
- 事件类型识别：
  - 登录事件（成功/失败登录、注销等）
  - 特权使用事件（特权提升、服务调用等）
  - 进程事件（进程创建、退出等）
  - 审计事件（策略变更、系统审核等）
  - 用户账户事件（账户创建、修改、删除等）
  - 组策略事件（域策略、筛选器变更等）
  - 服务事件（服务状态变更、安装等）
  - 防火墙事件（规则变更、连接阻止等）

### 2. 系统配置分析
- Windows 注册表安全检查
- Linux 系统配置评估
- 服务配置审计
- 安全策略检查

### 3. 网络安全分析
  - 活动连接实时监控
  - 可疑端口与连接检测
  - DNS 缓存安全分析
  - 网络行为异常识别
### 4. 平台特定功能
  - **Windows**
    - 注册表安全分析
    - 服务配置审计
    - 计划任务检查
    - 自启动项管理
  - **Linux**
    - 系统日志分析
    - 服务管理检查
    - 权限配置审计
    - 启动项检测

## 📊 数据分析

本项目生成的数据可以通过 [ProtectorPro Dashboard](https://github.com/yourusername/protectorpro-dashboard) 进行可视化分析。

### 数据格式

1. 事件日志 (CSV)
```csv
EventID,EventType,Time,Level,Source,Description,Computer,User
4624,Login,2024-12-21 22:00:00,Information,Security,成功登录,DESKTOP-XXX,user1
```

2. 系统配置 (JSON)
```json
{
  "timestamp": "2024-12-21T22:00:00Z",
  "system_info": {...},
  "security_settings": {...}
}
```

### 数据集成

1. 自动集成
   - 配置输出目录为 Dashboard 的监控目录
   - Dashboard 将自动导入新的数据文件

2. 手动导入
   - 通过 Dashboard 的文件上传功能
   - 支持批量导入历史数据

更多信息请参考 [Dashboard 文档](https://github.com/yourusername/protectorpro-dashboard)。

## 💻 使用方法

1. 运行工具
```bash
# Windows (需要管理员权限)
go run main.go

# Linux (需要 root 权限)
sudo go run main.go
```

2. 查看评估结果
- 事件日志保存在 `output/all_event_logs_[timestamp].csv`
- 筛选后的事件保存在 `output/filtered_event_logs_[timestamp].csv`
- 系统评估报告显示在控制台输出

## ⚠️ 免责声明

1. 本工具仅供安全研究和系统管理人员进行授权的安全评估使用。

2. 使用本工具进行评估时，您必须：
   - 确保您有权限对目标系统进行安全评估
   - 在您管理或授权的系统范围内使用
   - 遵守相关的法律法规和组织政策

3. 禁止行为：
   - 对未授权的系统进行评估
   - 利用本工具进行任何形式的攻击行为
   - 将本工具用于非法目的

4. 使用本工具造成的任何直接或间接损失，作者不承担任何责任。

## 🔧 系统要求

- 支持的操作系统：
  - Windows
  - Linux
- 运行权限：管理员/root 权限
- Go 1.16 或更高版本

## 📝 开发说明

本项目使用 Go 语言开发，采用模块化设计：
- `pkg/analyzer`: 核心分析引擎
- `pkg/eventlog`: 事件日志处理
- `pkg/registry`: 系统配置分析
- `pkg/scanner`: 资产扫描模块

## 🔜 开发计划 (TODO)
- [ ] 完善跨平台支持
- [ ] 增加更多安全检测规则
- [ ] 优化扫描性能
- [ ] 添加 Web 界面

## 📄 开源许可

本项目采用 MIT 许可证开源。
