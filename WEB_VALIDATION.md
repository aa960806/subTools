# 网页迁移验证记录

验证日期：2026-09-30。

## 范围与结果

- 完整功能回归：最终通过 792 项测试、102 项子测试。2 项浏览器测试默认跳过，已单独启用并通过；它们不是失败项。Windows Tk 测试退出时仍有原有 Tcl `after` 回调清理提示，测试断言全部通过，网页运行不加载 Tk。
- 网页及迁移：覆盖管理员登录、会话、CSRF、来源检查、秘密字段保留/清除、便携加密、错误密钥、配置迁移、原文件不变、任务串行、停止、刷新失败不自动重登、旋转 token 持久化、明确重登的身份检查、推池新增/更新、只读巡检、标准格式 ZIP、历史恢复、损坏记录提示、写盘失败收尾、暂缓恢复和浏览器输入隔离。
- Windows Chromium 实际页面测试：账号识别与模拟授权、授权结果转推池、五页导航、设置草稿保持、备用国家、配置分段控件、转换下载、历史打开、管理员退出清理、1440px / 430px 布局；无页面脚本错误。
- 浏览器人工接管：真实 Chromium 页面验证坐标点击、文本输入、按钮提交、截图、取消；不同账号之间不残留输入队列。
- Linux 部署镜像：在 WSL2 中的独立 Docker Engine 构建成功。实际运行验证登录/CSRF API、加密读写、转换下载、回调端口、静默及 Xvfb 可见 Chromium；服务器运行不导入 Tk。
- Linux 镜像内执行网页、迁移和浏览器回归：21 项通过。测试使用与正式镜像相同的用户和 Xvfb 入口；Starlette TestClient 有一条 httpx 兼容弃用提示，不影响运行服务。
- 私有数据迁移：3 份配置、79 个恢复文件；16 条 DPAPI 记录重加密，读取校验通过。迁移后网页显示 51 条可打开历史条目。旧工具完整 921 文件快照移动前后 SHA-256 清单一致。

## 保持原行为的边界

OAuth、短信和推池引擎保持原有状态机。迁移没有自动刷新真实账号、登录真实账号、购买短信、发送验证码或写入真实后台。容器烟雾测试使用离线页面和虚构数据；它证明服务器运行环境、接口和网页可用，不能证明某个外部账号在新服务器出口下能通过授权或风控。

网页任务在关闭网页后继续；停止会请求原引擎按既有规则收尾。已有发送/验证或不明确后台写入不能撤回。服务重启后不会自动恢复付费或登录操作；巡检定时器也需重新启用。

部署目标服务器的地址、域名和 SSH 信息未提供，因此本次交付为已验证的服务器部署源码和镜像构建配置，没有向未指定的远程服务器发布服务。

## 复现

```powershell
python -m pytest -q
$env:SUBTOOLS_BROWSER_TEST='1'
python -m pytest tests/test_web.py tests/test_migration.py tests/test_web_browser.py -q
```

```sh
docker build -t subtools:web .
docker run --rm --mount type=bind,src="$PWD/deploy/verify_runtime.py",dst=/app/verify_runtime.py,readonly subtools:web python verify_runtime.py
```

`data/`、旧快照、真实配置、密码、token、截图和本地测试环境均被 Git 与 Docker 构建上下文排除。管理员初始密码仅存在本地 `data/initial-password.txt`，不打印到日志或仓库。
