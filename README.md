# SubTools 网页账号工作台

独立的 Python / FastAPI 网页工具，用于 OpenAI / Codex OAuth 授权、手机补绑、格式转换和 sub2api 账号推送。维护目录为 `F:\SubTools`，不依赖 MySub2、桌面 exe 或正在运行的本地 sub2api。

## 功能

| 页面 | 保留的行为 |
| --- | --- |
| 批量授权 | 账号行、邮箱接码地址、sub2 / CPA / Session / 9router 输入；有凭据先刷新；刷新失败或结果不明需明确选择重登；优先非个人空间；代理、步骤等待、停止、重试、自动保存 |
| 手机接码 | 复用 OAuth 登录；SMSBower 中文国家与拼音排序、价格/库存匹配、主/备用国家、小/大重试、复用上限、超时及订单收尾；风控和余额不足仍停止；不会改成手机号注册 |
| 格式转换 | 文件/目录或粘贴导入、JSON 预览、丢失字段提示；完整 sub2 与标准九字段 CPA；多个 CPA 打包 ZIP，重名不覆盖 |
| 推送到池 | 管理员 Key / 访问令牌、读取分组多选、优先级、并发、后台代理、负载系数、模型同步与保留/删除；按用户和空间身份更新；手机验证跳过；不明确写入先核对 |
| 历史与巡检 | 加密任务恢复、只重试选中/未成功账号、暂缓、成功结果导出、待补手机转接码；只读巡检及当前服务内的定时巡检，不自动刷新或重登 |

任务在服务器后台运行，关闭或刷新网页不会停止。一个服务同时运行一个处理任务；并发配置仍指 sub2api 后台账号并发。服务重启后保留任务记录，由用户检查后手动恢复，不自动买号、登录或推送。定时巡检需重新启用。

勾选“显示浏览器”后，Playwright 在服务器上运行有界面浏览器；在网页点击“查看登录浏览器”，可点击画面、输入文字、发送按键，人工处理登录交互。浏览器截图只保存在内存，不开放 CDP/VNC 端口。画面约每秒更新，导航或网络阻塞时可能暂时停顿。

## Linux 服务器部署（Docker Compose）

需要 Docker Engine 和 Compose。建议至少 2 核 CPU、2 GB 内存；浏览器运行时推荐 4 GB。

```sh
git clone https://github.com/aa960806/subTools.git
cd subTools
cp .env.example .env
```

编辑 `.env`：将 `SUBTOOLS_PUBLIC_ORIGIN` 设置为访问该工具的完整 URL，如 `https://subtools.example.com`；首次启动设置至少 12 位的唯一 `SUBTOOLS_ADMIN_PASSWORD`。已有迁移的 `data/admin.json` 时继续使用原管理员密码。

```sh
docker compose up -d --build
docker compose logs --tail 50
```

服务默认仅绑定服务器 `127.0.0.1:8787`。在 Nginx HTTPS 站点中使用 [反向代理示例](deploy/nginx.conf.example)。开发机可以用 `http://localhost:8787` 并把 `.env` 中的 URL 改为同一地址。正式访问使用 HTTPS，避免账号信息通过明文传输。

容器内置 Chromium、字体和 Xvfb。OAuth 固定回调 `http://localhost:1455/auth/callback` 发生在同一容器内，**无需映射 1455**。不需要在访问网页的电脑安装 Python、浏览器驱动或桌面工具。

首次初始化后可从 `.env` 删除初始密码。网页 Cookie 为 HttpOnly、SameSite=Strict，写操作校验 CSRF；管理员登录有失败次数限制。该工具是单管理员的私有工作台，不是面向陌生用户的多租户服务。

## 配置、历史与迁移

所有运行数据位于 `data/`，不进入 Git 或 Docker 镜像：

- `master.key`：本安装的数据加密密钥；迁移和备份必须与数据一起保留。
- `admin.json`、`config/`、`tasks/`：管理员密码哈希、连接配置、账号任务，以 Fernet 加密保存。
- `recovery/`：原引擎的刷新恢复、SMS 订单、绑定报告、成功 JSON；成功导出仍含可用 token，应按私有凭据保护整个目录。
- `legacy-desktop/`：搬迁时保留的完整原工具快照，含旧配置和备份；仅供本地回溯，旧 DPAPI 数据只能在原 Windows 用户下解密。
- `migration-manifest.json`：加密迁移清单和文件哈希。

本次迁移后，原 Windows 配置和恢复记录已转入新的 `data/`。上传服务器时通过私有传输复制 `data/`，不要添加到 Git。运行所需内容是 `master.key`、`admin.json`、`config/`、`tasks/`（如有）和 `recovery/`；旧桌面快照可留在本机，不必上传。停服后复制可以得到一致备份。

```sh
docker compose stop
# 私有备份整个 data/；恢复时保持 master.key 与密文一致。
docker compose up -d
```

迁移其他旧桌面安装时，在原 Windows 用户下执行以下命令（目标须为空，脚本不会修改原文件或调用外部账号）：

```powershell
python migrate_desktop.py "D:\path\to\old-tool" --data "D:\path\to\new-data"
```

服务器网络模式“系统代理”读取**服务器**的 `HTTPS_PROXY` / `ALL_PROXY` / `HTTP_PROXY`；Windows 读取当前 Windows 静态代理。它不会继承访问网页那台电脑的代理。容器中 `127.0.0.1` 指容器自身；自定义代理须填服务器可达的地址。

## 本机维护与非 Docker 运行

Python 3.12 或 3.13：

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.venv\Scripts\python.exe -m playwright install chromium
.venv\Scripts\python.exe setup_admin.py
.\start.bat
```

`start.bat` 启动网页服务并打开本机网页。Linux 非 Docker 部署安装 Chromium 系统依赖、`xvfb` 和 `xauth` 后执行 `sh start.sh`。用进程管理器保持服务，设定 `SUBTOOLS_HOST` / `SUBTOOLS_PORT` 时同步配置反向代理。只允许一个 Uvicorn worker，第二个进程会被数据目录锁拒绝。

忘记管理员密码：先停止服务，在安装目录执行 `python setup_admin.py --reset`。容器环境可用：

```sh
docker compose stop
docker compose run --rm -it subtools python setup_admin.py --reset
docker compose up -d
```

代码入口：`web_app.py`（认证与 API）、`server_engine.py`（后台任务）、`web/`（界面）。原有授权、短信和推池引擎继续在根目录维护。Tk 模块仅保留为兼容参考及回归测试对象，网页运行不导入它们。

## 验证

```sh
python -m pytest -q
SUBTOOLS_BROWSER_TEST=1 python -m pytest tests/test_web_browser.py -q
```

Windows PowerShell 启用浏览器测试：`$env:SUBTOOLS_BROWSER_TEST='1'`。测试使用虚构账号与模拟接口，不购买短信号码、不更改真实后台账号。完整验证范围和部署限制见 [WEB_VALIDATION.md](WEB_VALIDATION.md)。外部授权、短信库存和后台可用性仍受实际服务器网络与上游返回影响。

参考来源和许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。旧桌面说明保存在 [docs/desktop-legacy.md](docs/desktop-legacy.md)，不作为网页部署步骤。
