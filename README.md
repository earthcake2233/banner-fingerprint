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
 "rules":{"source":"/etc/fingerprint/rules.yaml","count":21,"loaded_at":"...","reloaded":true,"error":""}}
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
scripts/verify.sh              # 端到端验收：vet + 单测 + 起服务 + 20 项 HTTP 契约/边界检查，逐项打印 PASS/FAIL
make test                      # 单元测试（识别深度、unknown 不报错、容错解析、HTTP 行为）
make vet                       # go vet
docker build --target test .   # 在容器里跑 vet + 测试
```

样例数据：

| 文件 | 用途 |
|------|------|
| `samples/task-example-input.json` | 题目给的 20 条参考输入（原样保留） |
| `samples/task-example-expected.json` | 题目给的参考输出，被 `TestTaskExampleMatchesExpectedOutput` **逐字段断言** |
| `samples/input.json` | 与参考输入等价的严格 JSON 版本（compose 里 client 的默认输入） |
| `samples/input-messy.txt` | 故意写成非法 JSON（`\xNN` 转义），验证容错解析 |

## 验证记录

开发环境里的实测结果（不是设计稿，是跑出来的）：

| 验证项 | 命令 | 结果 |
|--------|------|------|
| 参考样例逐字段比对 | `go test ./internal/fingerprint -run TestTaskExample -v` | 题目给的 7 行参考输出**逐字段完全一致**（含空 `os_hint`、空 `version`、`confidence` 精确值） |
| 参考数据识别率 | `go test -run TestEveryReferenceRecordIsIdentified -v` | 20 条输入 → 19 识别、1 unknown；直方图 `FTP:3 HTTP:7 MySQL:2 Redis:3 SSH:3 TLS:1 unknown:1` |
| 单元测试 | `go vet ./... && go test ./...` | 全部通过（fingerprint / jsonutil / httpapi 三个包） |
| 端到端验收脚本 | `scripts/verify.sh` | **20/20 PASS**：健康检查、批量识别、explain、逐行 verbatim 比对、空批次、400/405/404/413、非法转义容错、unknown 不报错，以及 200 批（每批 20 条）压测 2s 内完成且服务仍 healthy |
| compose 语法 | `docker compose config --quiet` | 通过 |
| 镜像构建 | `docker build --target test .` / `docker build .` | 两个阶段都成功；容器内 `go vet` + 单测全绿；runtime 镜像 32MB |
| 一键启动 | `COMPOSE_BAKE=false docker compose up -d --build server` | 一条命令完成构建 + 启动：`server  Up (healthy)  127.0.0.1:8080->8080/tcp` |
| 健康检查 | `curl 127.0.0.1:8080/health` | `{"rules":{"source":"/etc/fingerprint/rules.yaml","count":21},"status":"ok"}` |
| 批量识别（宿主回环） | `curl -X POST 127.0.0.1:8080/fingerprint -d @samples/task-example-input.json` | 20 条 → 19 识别成功，1 条 unknown，字段与题目示例一致 |
| 容错解析 | `client -input samples/input-messy.txt`（非法 `\xNN` 转义） | 5 条全部正常返回，未报错 |
| 规则溯源 | `client -explain` | 每条带 `rule_id`（如 `ssh-openssh`、`mysql-greeting`） |
| 容器内网访问 | `docker compose run --rm client` | client 容器经 `http://server:8080` 取到全部结果，未走宿主端口 |
| 容器加固 | `docker inspect banner-fingerprint-server-1` | `ReadonlyRootfs=true CapDrop=[ALL] SecOpt=[no-new-privileges:true] User=65532:65532 Pids=256 Mem=256MB` |
| 规则热加载 | 往 `rules/rules.yaml` 追加一条规则 | 不重启、不重建：`/health` 的 `count` 从 21 → 22，新规则立即生效 |
| 坏规则容错 | 把 `rules/rules.yaml` 写成非法 YAML | 服务保持 `healthy`，`/health` 回显解析错误，**继续用旧规则识别**（SSH 仍正常返回）；恢复文件后自动回滚成功 |
| 日志/优雅停机 | 服务端日志 | JSON 结构化日志，含 `request_id`/`status`/`duration_ms` |

验证过程中实际发现并已修复的两个缺陷（都已推到仓库）：

1. `test` 构建阶段没把 `rules/`、`samples/` 拷进构建上下文，容器内测试读不到文件 → 修复后 `docker build --target test .` 全绿；
2. 引擎默认会给结果带上 `rule_id`，而接口契约只允许 7 个字段 → 改为库的默认输出就不含 `rule_id`，
   只有 `?explain=1` 才追加（`TestResultJSONContract` 断言 JSON 键集合正好是 7 个）。

样例数据的实际输出（节选）：

```text
IP        PORT   PROTOCOL  PRODUCT        VERSION  OS_HINT  CONF
1.2.3.4   22     SSH       OpenSSH        8.9p1    Ubuntu   0.95
1.2.3.5   80     HTTP      nginx          1.24.0   -        0.90
1.2.3.6   443    HTTP      Apache         2.4.57   -        0.90
1.2.3.7   3306   MySQL     MySQL          8.0.32   -        0.90
1.2.3.8   6379   Redis     Redis          -        -        0.70
1.2.3.9   21     FTP       ProFTPD        1.3.7    -        0.90
1.2.3.10  8080   HTTP      Jetty          9.4.51   -        0.85
...
1.2.3.23  12345  unknown   -              -        -        0.00

20 records: 19 identified, 1 unknown
protocols: FTP=3, HTTP=7, MySQL=2, Redis=3, SSH=3, TLS=1, unknown=1
```

复现整套流程：

```bash
docker compose up --build        # 等价于：构建镜像 -> 起 server -> 等 /health 转绿 -> 跑 client 打印结果
docker compose ps                # server 应为 healthy
```

## 已知边界

- 只做"给定 banner 的离线识别"：不主动发起扫描、不做 TLS 握手或 HTTP 请求（避免把指纹系统变成扫描器）；
- 版本号依赖 banner 自曝，伪造 banner 可能被误判——`confidence` 就是给这种不确定性留的余量；
- 规则是"高优先级命中即停"的线性匹配；规则到数千条量级时建议再加端口/前缀索引（当前 21 条无需）。

## 排障

- `docker compose build` 报 `panic: slice bounds out of range`：这是部分 compose v2.40.x 的 bake 缺陷
  （用一个最小 compose 项目同样能复现，与本项目的 compose 文件无关）。绕过方式：
  `COMPOSE_BAKE=false docker compose up -d --build`，或先 `docker build -t banner-fingerprint:local .`
  再 `docker compose up --no-build`。
- 拉不到 `golang:1.26-alpine` / `alpine:3.21`：若本机走镜像加速，把对应镜像 retag 成这两个名字即可离线构建
  （构建阶段本身不需要网络，依赖已 vendor）。
