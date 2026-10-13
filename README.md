# banner-fingerprint

接收一批网络扫描原始数据（`ip` / `port` / `banner`），识别出对应的**协议 / 软件 / 版本 / 操作系统线索**，以
**client + server** 架构交付，`docker compose up` 一键启动。

识别知识（正则规则）全部放在 `rules/rules.yaml` 里，改规则不需要改代码、不需要重新编译、不需要重启服务。

## 快速开始

```bash
# 1. 启动（server + 一次性 client 演示），首次会构建镜像
docker compose up --build

# 2. 看识别结果：client 容器会把 20 条样例数据打成一张表；
#    也可以直接打接口（端口只绑在宿主回环上）
curl -sS -X POST 127.0.0.1:8080/fingerprint \
     -H 'Content-Type: application/json' \
     --data-binary @samples/input.json | jq .

# 3. 用你自己的数据跑 client（把文件放进 ./samples/ 即被挂载为 /data）
docker compose run --rm client -input /data/your-file.json -format table

# 4. 收工
docker compose down
```

本地不开 Docker 也可以跑：`make run-server` 然后另开一个终端 `make run-client`。

## 架构

```
            +----------------------------+         +----------------------------------+
 扫描数据   |  client (一次性容器 / CLI)  |  HTTP   |  server (常驻容器)                |
 JSON 文件 ---> 读取本地文件              |-------->|  POST /fingerprint   批量识别     |
            |  JSON 容错解析              |  容器   |  GET  /health        健康检查     |
            |  表格 / JSON 展示           |  内网   |  GET  /rules         规则目录     |
            +----------------------------+         +----------------+-----------------+
                                                              | 加载
                                              rules/rules.yaml（挂载进容器，可热加载）
```

- **server**：无状态 HTTP 服务，启动时加载规则；规则文件变更后 15s 内自动热加载（收到 `SIGHUP` 也会立即重载）。
- **client**：独立程序，读本地 JSON、调用 server、打印结果；server 未就绪时会自动重试。
- 两者共用**同一个镜像**（`ENTRYPOINT` 是 server，client 服务用 `entrypoint` 覆盖），版本不会漂移。

## 识别能力（自测样例的实际输出）

| 样例 | protocol | product | version | os_hint | conf |
|------|----------|---------|---------|---------|------|
| 1.2.3.4:22 | SSH | OpenSSH | 8.9p1 | Ubuntu | 0.95 |
| 1.2.3.5:80 | HTTP | nginx | 1.24.0 | | 0.90 |
| 1.2.3.6:443 | HTTP | Apache | 2.4.57 | | 0.90 |
| 1.2.3.10:8080 | HTTP | Jetty | 9.4.51 | | 0.85 |
| 1.2.3.11:22 | SSH | OpenSSH | 9.3 | Debian | 0.95 |
| 1.2.3.12:80 | HTTP | nginx | 1.18.0 | Ubuntu | 0.90 |
| 1.2.3.7 / 14:3306 | MySQL | MySQL | 8.0.32 / 5.7.42 | | 0.90 |
| 1.2.3.8 / 15 / 21:6379 | Redis | Redis | | | 0.70 |
| 1.2.3.9:21 | FTP | ProFTPD | 1.3.7 | | 0.90 |
| 1.2.3.16:21 | FTP | vsFTPd | 3.0.5 | | 0.90 |
| 1.2.3.22:21 | FTP | Pure-FTPd | | | 0.85 |
| 1.2.3.20:8888 | HTTP | Microsoft-IIS | 10.0 | | 0.90 |
| 1.2.3.19:9999 | TLS | | | | 0.60 |
| 1.2.3.23:12345 | unknown | | | | 0.00 |

识别不出来就是 `protocol: "unknown"`、`confidence: 0` 的正常结果，**不会报错、不会中断整批请求**。

## HTTP API

### `POST /fingerprint`

请求体接受多种形态（自动识别，无需配置）：

```text
[ {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"} ]   数组
{"items":[ ... ]}                                                         信封（items/data/records/results/hosts/inputs/banners/rows）
{"ip":"1.2.3.4","port":22,"banner":"..."}                                  单条对象
{"ip":"..."} 换行 {"ip":"..."}                                             NDJSON / JSON Lines
```

字段名容错：`ip|ip_address|host|address`、`port|port_number|dst_port`（数字或字符串）、
`banner|data|response|raw|payload|service_banner`；多余字段（时间戳、ASN 等）会被忽略。
扫描器常见的 `\x00` 这类 **C 风格转义（严格 JSON 非法）会自动修复**，整批数据不会因为一个字节而报废。

响应：默认是**与请求等长的 JSON 数组**，字段固定为 7 个：

```json
[{"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95}]
```

可选查询参数：

| 参数 | 作用 |
|------|------|
| `?wrap=1` | 返回 `{"count":N,"unknown":K,"results":[...]}` |
| `?explain=1` | 每条结果附加 `rule_id`，说明是哪条规则命中的（便于调规则） |

### `GET /health`

```json
{"status":"ok","version":"local","uptime_s":12,
 "rules":{"source":"/etc/fingerprint/rules.yaml","count":24,"loaded_at":"...","reloaded":true,"error":""}}
```

`docker compose` 的 server 健康检查就是调用它（用服务自己的二进制 `-healthcheck` 探测，镜像里不需要 curl）。

### `GET /rules`

列出当前生效的规则目录（id / protocol / product / priority / confidence / ports）。

## 识别规则（与代码解耦）

规则文件：`rules/rules.yaml`（同时内嵌一份到二进制里作为兜底，两者由 `make sync-rules` 保持同步，
`go test` 会断言它们一致）。也支持 JSON、支持目录（目录下所有 `*.yaml|*.yml|*.json` 按文件名合并）。

```yaml
rules:
  - id: ssh-openssh                 # 唯一 id，?explain=1 时会回显
    description: OpenSSH ident string
    priority: 100                   # 越大越先匹配，命中即停
    protocol: SSH
    product: OpenSSH                # 支持 {捕获组} 模板
    version: "{version}"
    confidence: 0.95                # 0~1
    ports: []                       # 可选端口白名单，空 = 任意端口
    banner_any:                     # 至少一条正则命中
      - '^SSH-[0-9.]+-OpenSSH_(?P<version>[0-9][0-9A-Za-z._p]*)'
    banner_all: []                  # 每条正则都必须命中
    banner_none: []                 # 命中任意一条则否决本规则
    os_hint:                        # 第一条命中的正则决定 os_hint
      - { name: Ubuntu, regex: '(?i)\bubuntu\b' }
```

匹配语义：`ports` 通过 → `banner_any` 至少一条命中 → `banner_all` 全命中 → `banner_none` 全不命中。
命名捕获组 `(?P<name>...)` 会喂给 `{name}` 模板（先匹配到的模式优先生效）。

**新增一个协议**：往 `rules/rules.yaml` 里加一条规则即可。容器把 `./rules` 只读挂到 `/etc/fingerprint`，
server 每 15s 比对 mtime/size 自动热加载；规则文件语法错误时**保留旧规则继续服务**，并把错误写进 `/health`。

## 目录结构

```
cmd/server                      HTTP 服务入口（同时是自己的 healthcheck 探针）
cmd/client                      CLI：读文件 -> 调接口 -> 打印表格 / JSON
internal/fingerprint            规则模型 + 正则匹配引擎 + 热加载 Store
internal/fingerprint/builtin    内嵌的兜底规则
internal/httpapi                HTTP 层：路由、中间件、请求日志、panic 兜底
internal/jsonutil               容错 JSON 解析（数组 / 信封 / NDJSON、\xNN 修复、双引号修复）
rules/rules.yaml                识别规则（数据）
samples/                        自测样例（含一份故意写成非法 JSON 的容错样例）
compose.yaml                    一键启动编排
Dockerfile                      多阶段构建（vendor 免网络编译 / test 阶段 / 最小运行时）
Dockerfile.distroless           更极致的运行时（distroless/static，无 shell）
```

## 生产级部署说明

**容器间访问收敛**

- 只有 server 发布端口，且只绑在**宿主回环** `127.0.0.1:8080`，局域网访问不到；
- client 不走宿主端口，直接通过 compose 网络的服务名访问 `http://server:8080`；
- 二者只在自建的 `fingerprint` bridge 网络内互通。

**启动依赖是真实健康检测**

- server 的 `HEALTHCHECK` 用自身二进制请求 `http://127.0.0.1:8080/health`（真实 HTTP 探测，不是"进程还在"）；
- client 用 `depends_on: {server: {condition: service_healthy}}` 等它转绿；即便提前启动也会带重试等待。

**镜像与构建**

- 三个阶段：`build`（编译）→ `test`（`go vet` + 单测，`docker build --target test .` 可单独跑）→ 运行时；
- 依赖**已 vendor 进仓库**，`go build -mod=vendor` 不需要访问 Go proxy，构建可离线复现；
- `CGO_ENABLED=0` 静态二进制 + `-trimpath -ldflags="-s -w"`，运行镜像里没有编译器、没有 Go 工具链；
- 版本号通过 `-X main.version=...` 注入（`docker compose build --build-arg VERSION=...`）；
- 想更极致可换 `Dockerfile.distroless`（无 shell、无包管理器、无 libc 工具）。

**运行时权限收紧**

`read_only: true`（根文件系统只读，仅 `/tmp` 为 tmpfs）、`cap_drop: [ALL]`、
`security_opt: [no-new-privileges:true]`、`user: "65532:65532"`（非 root）、
`pids_limit` / `mem_limit` / `cpus` 限额、日志轮转 `max-size` / `max-file`。

**可观测性**

- JSON 结构化日志（`slog`）输出到 stdout，每条请求带 `request_id`、状态码、耗时、字节数；
- 单个请求 panic 由中间件兜住并返回 500，进程不退出；优雅停机（SIGTERM → 10s 排空连接）。

## 配置项

| 环境变量 / flag | 默认值 | 说明 |
|------|------|------|
| `FP_ADDR` / `-addr` | `:8080` | 监听地址 |
| `FP_RULES` / `-rules` | `/etc/fingerprint/rules.yaml` -> `rules/rules.yaml` -> 内嵌 | 规则文件或目录 |
| `FP_RULES_WATCH` / `-rules-watch` | `15s` | 规则热加载轮询间隔，`0` 关闭 |
| `FP_MAX_BODY_MB` / `-max-body-mb` | `16` | 单次请求体上限 |
| `FP_LOG_LEVEL` / `-log-level` | `info` | 日志级别 |
| `FP_SERVER_URL` / `-url`（client） | `http://127.0.0.1:8080` | 服务地址 |
| `FP_INPUT` / `-input`（client） | `samples/input.json` | 输入文件，`-` 表示 stdin |
| `-healthcheck <url>`（server） | | 探活模式，容器健康检查用 |

## 自测

```bash
make test                      # 单元测试（识别深度、unknown 不报错、容错解析、HTTP 行为）
make vet                       # go vet
docker build --target test .   # 在容器里跑 vet + 测试
```

样例数据：`samples/input.json`（20 条，覆盖 SSH / HTTP / MySQL / Redis / FTP / TLS / 未知），
`samples/input-messy.txt`（故意使用非法 JSON 转义，用来验证容错解析）。

## 已知边界

- 只做"给定 banner 的离线识别"：不主动发起扫描、不做 TLS 握手或 HTTP 请求（避免把指纹系统变成扫描器）；
- 版本号依赖 banner 自曝，伪造 banner 可能被误判——`confidence` 就是给这种不确定性留的余量；
- 规则是"高优先级命中即停"的线性匹配；规则到数千条量级时建议再加端口/前缀索引（当前 24 条无需）。
