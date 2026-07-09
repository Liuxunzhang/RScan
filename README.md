# RSCAN

Rust 重写版内网综合扫描工具工作区，目标是**独立复现原 `fscan` 的功能与行为**，但仓库本身**不再依赖原 Go 项目的目录结构或源码路径**。

## 特性

- 主机存活探测、端口扫描、结果输出
- 服务插件扫描与弱口令检测
- Web 标题、指纹、POC 扫描
- 本地信息采集与部分本地模块
- 服务指纹识别与 Go 行为兼容回归

## 构建

```bash
cargo build --release
```

默认产物：

```bash
target/release/rscan
```

## 使用

```bash
# 主机/端口扫描
./target/release/rscan -h 192.168.1.10/24

# 开启服务指纹
./target/release/rscan -h 192.168.1.10 -p 22,80,445 -fingerprint

# 仅扫描 URL
./target/release/rscan -u http://127.0.0.1:8080

# 指定模块
./target/release/rscan -h 192.168.1.10 -m ssh -user root -pwd 123456
```

完整参数：

```bash
./target/release/rscan -h
```

## 开发与质量检查

提交前建议运行：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --no-fail-fast
cargo build --release --workspace
```

如果安装了 `just`，也可以运行：

```bash
just check-all
```

仓库已提供 GitHub Actions CI，用于自动执行格式化、Clippy、测试和 release 构建检查。

## 仓库说明

- `cli/`：命令行入口
- `config/`：参数解析与运行配置
- `core/`：扫描编排
- `fingerprint/`：服务指纹识别
- `plugins/`：服务插件与漏洞/弱口令模块
- `poc/`：Web POC 引擎
- `web/`：Web 探测与指纹
- `net/`：目标展开、探测与端口扫描

## 独立性

当前仓库已内置运行所需的兼容资源，包括：

- `fingerprint/assets/nmap-service-probes.txt`
- `fingerprint/assets/Config.go`
- `web/assets/Rules.go`
- `poc/embedded-pocs/`
- `plugins/assets/MS17010-Exp.go`

因此将本目录单独复制或初始化为新的 Git 仓库后，代码不再依赖外层 `fscan/` 目录。
