# decentid 使用说明

`decentid` 是一个用 Go 编写的去中心化身份原型。它不是传统账号系统，而是用 `did:p2p:<hash(rootPublicKey)>`、签名事件链、challenge-response、memory / attestation 对象来验证去中心化身份模型。

> 概念不清先看 [`概念模型.md`](./概念模型.md)：核心只有 3 个（身份=密钥、连续性=签名链、登录=签名），并附术语对照表。

## 1. 进入项目目录

```bash
cd D:/Dev/ai/code/run/id
```

## 2. 安装 / 整理依赖

需要 Go 1.24+。

```bash
go mod tidy
```

## 3. 创建身份

```bash
go run ./cmd/decentid create -name alice -out alice.json
```

会生成本地身份文件 `alice.json`，里面包含身份文档、事件链、本地 keyring 和私钥。

注意：当前是原型，私钥明文保存在 JSON 里，不要提交到公开仓库。

## 4. 查看身份

```bash
go run ./cmd/decentid show -identity alice.json
```

## 5. 添加 memory

### public memory

```bash
go run ./cmd/decentid add-memory -identity alice.json -type note -payload "hello public"
```

### private memory

```bash
go run ./cmd/decentid add-memory -identity alice.json -type note -payload "secret memory" -visibility private
```

查看 / 解密本地 private memory：

```bash
go run ./cmd/decentid show-memory -identity alice.json -memory <memoryCID>.json
```

## 6. 管理设备 key

添加设备：

```bash
go run ./cmd/decentid add-device -identity alice.json -label laptop
```

查看 key：

```bash
go run ./cmd/decentid keys -identity alice.json
```

撤销设备：

```bash
go run ./cmd/decentid revoke-device -identity alice.json -key-id <deviceKeyId> -reason "lost"
```

## 7. challenge-response 登录验证流程

生成 challenge：

```bash
go run ./cmd/decentid challenge -id "did:p2p:..." -out challenge.json
```

用身份响应：

```bash
go run ./cmd/decentid respond -identity alice.json -challenge challenge.json -out response.json
```

导出公开身份状态给验证方：

```bash
go run ./cmd/decentid export-state -identity alice.json -out alice-state.json
```

验证响应：

```bash
go run ./cmd/decentid verify -state alice-state.json -response response.json
```

`alice.json` 是本地私有身份文件，包含私钥材料，不应该交给验证方；验证方只需要公开的 `alice-state.json`。

也可以指定设备 key：

```bash
go run ./cmd/decentid respond -identity alice.json -challenge challenge.json -signer-key-id <deviceKeyId> -out response.json
```

## 8. 轮换 root key

```bash
go run ./cmd/decentid rotate-root -identity alice.json -label rotated-root
go run ./cmd/decentid show -identity alice.json
```

DID 不会改变，root rotation 只改变控制 key。

## 9. attestation

签发：

```bash
go run ./cmd/decentid issue-attestation -identity issuer.json -subject "did:p2p:..." -claim-type known -claim-value alice -out attestation.json
```

验证：

```bash
go run ./cmd/decentid verify-attestation -issuer issuer.json -attestation attestation.json
```

附着到身份：

```bash
go run ./cmd/decentid attach-attestation -identity alice.json -attestation attestation.json
```

## 10. P2P 发布与解析

终端 A 发布：

```bash
go run ./cmd/decentid publish -identity alice.json -wait 10m
```

如果不想发布 attestation：

```bash
go run ./cmd/decentid publish -identity alice.json -wait 10m -include-attestations=false
```

终端 B 解析：

```bash
go run ./cmd/decentid resolve -peer "<peer-multiaddr>" -id "did:p2p:..."
```

当前 `publish` 会发布：

- signed identity state
- public memory manifest / object
- 已附着的 attestation object

不会发布 private memory。

## 11. 常用验证命令

改完代码后通常跑：

```bash
gofmt -w ./cmd ./internal ./pkg
go test ./...
go vet ./...
```

## 12. 最小体验流程

如果只是想快速跑通：

```bash
cd D:/Dev/ai/code/run/id

go run ./cmd/decentid create -name alice -out alice.json
go run ./cmd/decentid show -identity alice.json
go run ./cmd/decentid add-memory -identity alice.json -type note -payload "hello public"
go run ./cmd/decentid keys -identity alice.json
go test ./...
```
