# decentid

`decentid` 是一个用 Go 编写的去中心化身份原型，用来验证这样一条最小可运行主线：
- DID 不依赖中心登录服务器
- DID 固定来自首次 root public key，而不是来自可变 memory 内容
- identity continuity 由 append-only 签名事件链保证
- challenge-response 只依赖身份状态和签名，不依赖中心账号系统
- memory / attestation 都是独立内容对象，通过 CID 挂到身份之下
- 节点间通过 libp2p 交换 identity state 和对象

> 这是协议原型，不是生产级 DID 平台。重点是把身份模型、事件回放验证、密钥生命周期、私有 memory 加密和最小 P2P 流程跑通。

详细的第二版实现规划、关键文件、验收清单见 [`PLAN.md`](./PLAN.md)。

## 当前状态

### 第一版已跑通

- Go 模块与 CLI 骨架
- DID 生成
- 签名事件链
- public memory
- challenge-response
- 最小 libp2p 解析

### 第二版已补齐

- replay-based state verification
- 本地 keyring
- key rotation + device add / revoke
- attestation 签发 / 验证 / 附着
- 私有 memory 加密

## 当前已实现

- Ed25519 root key / device key
- X25519 encryption key
- `did:p2p:<hash(rootPublicKey)>` 身份生成
- append-only identity event chain
- 基于 event replay 的状态验证
- 本地 keyring 导入导出（`localKeys` + preferred key IDs）
- device add / revoke
- root rotate（DID 保持不变）
- public memory manifest / object
- private memory 加密、private memory root、本地解密
- challenge-response 身份验证
- standalone attestation 签发 / 验证 / 附着
- libp2p 远端 state 解析与对象拉取
- CLI 原型

## 当前未实现

- shared / multi-recipient private memory
- 持久化 object store
- 基于 provider routing 的对象发现
- 长期运行节点与后台同步
- 完整的 trust / reputation policy
- 生产级密钥托管、恢复与硬件保护

## 协议关键规则

### DID 来自首次 root public key

主身份固定为：

```text
did:p2p:<hash(rootPublicKey)>
```

这意味着：
- profile 变化不会改 DID
- memory 变化不会改 DID
- root rotate 表示控制权连续性，不表示 DID 重算

### 历史验证必须按事件回放

当前 `VerifyState` 不是用最终 document 去验所有历史事件，而是：
1. 从 `CreateIdentity` 初始化工作态 document
2. 按顺序逐条 event 校验 `PrevEventID`
3. 用当时有效的 key 解析 signer
4. 验签
5. 把 event 应用到工作态 document
6. 最后把回放结果与最终 `SignedIdentityState.Document` 比对

这样才能保证 revoke / rotate 之后，历史合法签名不会被误判。

### 本地身份文件是 keyring，不是双私钥快照

本地身份文件现在保存：
- `document`
- `events`
- `localKeys[]`
- `preferredRootKeyId`
- `preferredDeviceKeyId`
- `preferredEncryptionKeyId`

说明：
- 本地可以持有多把 root / device / encryption key
- public `IdentityDocument` 不包含任何私钥
- 网络状态验证不能依赖“本地正好持有哪把私钥”

### private memory 必须是真加密

`visibility=private` 不只是标签：
- 对象文件里不保存明文 payload
- 使用 X25519 + AES-GCM 生成密文
- identity document 更新的是 `privateMemoryRoot`
- `publish` 默认不会把 private memory 发布到 P2P object store

### attestation 是独立对象

attestation 的流转是：
- issuer 先签发独立 `Attestation` 对象
- subject 再通过 event 附着 attestation CID
- `publish` 默认会连同已附着 attestation 一起发布；可用 `-include-attestations=false` 关闭

## 代码结构

- `cmd/decentid/`：统一单二进制入口（`web` 子命令 + 全部 node 子命令）
- `internal/cli/`：node / web 子命令的实现，供统一入口调用
- `pkg/types/`：共享结构定义
- `internal/crypto/`：Ed25519、X25519、哈希、canonical JSON
- `internal/identity/`：身份创建、事件链、回放验证、本地 keyring
- `internal/memory/`：memory object / manifest、私有 memory 加密
- `internal/auth/`：challenge-response
- `internal/attestation/`：attestation 创建、签名、验证
- `internal/p2p/`：libp2p resolver、state / object exchange
- `internal/app/`：操作服务层，复用协议能力并隐藏默认私钥输出
- `internal/web/`：HTTP handlers、templates、static assets

## 环境要求

- Go 1.24+

## 安装依赖

```bash
go mod tidy
```

## 构建单一二进制

项目是纯 Go、无 CGO；Web 模板与静态资源通过 `go:embed` 打进二进制，运行时不依赖任何外部文件，因此可以编出一个自包含的单文件 `decentid`。

```bash
# 当前平台 -> dist/decentid[.exe]
scripts/build.sh

# 跨平台发布矩阵（linux/darwin/windows × amd64/arm64）-> dist/
scripts/build.sh all

# 或直接用 go build
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o decentid ./cmd/decentid
```

统一二进制用法：

```bash
decentid web -identity alice.json -addr 127.0.0.1:8080   # 启动本地操作台
decentid create -name alice -out alice.json              # 其余子命令即原 CLI
decentid version
```

下文示例中的 `go run ./cmd/decentid ...` 与已构建的 `decentid ...` 可互换。

## 快速开始

### 1. 创建身份

```bash
go run ./cmd/decentid create -name alice -out alice.json
```

### 2. 查看身份

```bash
go run ./cmd/decentid show -identity alice.json
```

### 3. 添加 public memory

```bash
go run ./cmd/decentid add-memory -identity alice.json -type note -payload "hello public"
```

### 4. 添加 private memory

```bash
go run ./cmd/decentid add-memory -identity alice.json -type note -payload "secret memory" -visibility private
go run ./cmd/decentid show-memory -identity alice.json -memory <memoryCID>.json
```

### 5. 添加 / 撤销设备

```bash
go run ./cmd/decentid add-device -identity alice.json -label laptop
go run ./cmd/decentid keys -identity alice.json
go run ./cmd/decentid revoke-device -identity alice.json -key-id <deviceKeyId> -reason "lost"
```

### 6. challenge-response

```bash
go run ./cmd/decentid export-state -identity alice.json -out alice-state.json
go run ./cmd/decentid challenge -id "did:p2p:..." -out challenge.json
go run ./cmd/decentid respond -identity alice.json -challenge challenge.json -out response.json
go run ./cmd/decentid verify -state alice-state.json -response response.json
```

`alice.json` 是本地私有身份文件，不应该交给验证方；验证方使用公开的 `alice-state.json` 验证 response。

显式指定设备 key：

```bash
go run ./cmd/decentid respond -identity alice.json -challenge challenge.json -signer-key-id <deviceKeyId> -out response.json
```

### 7. rotate root

```bash
go run ./cmd/decentid rotate-root -identity alice.json -label rotated-root
go run ./cmd/decentid show -identity alice.json
```

### 8. attestation

```bash
go run ./cmd/decentid issue-attestation -identity issuer.json -subject "did:p2p:..." -claim-type known -claim-value alice -out attestation.json
go run ./cmd/decentid verify-attestation -issuer issuer.json -attestation attestation.json
go run ./cmd/decentid attach-attestation -identity alice.json -attestation attestation.json
```

### 9. P2P publish / resolve

终端 A：

```bash
go run ./cmd/decentid publish -identity alice.json -wait 10m
```

如果不想发布已附着 attestation：

```bash
go run ./cmd/decentid publish -identity alice.json -wait 10m -include-attestations=false
```

终端 B：

```bash
go run ./cmd/decentid resolve -peer "<peer-multiaddr>" -id "did:p2p:..."
```

当前 publish 行为：
- 发布 signed identity state
- 放入 public memory manifest / object
- 默认放入 attached attestation object
- **不会发布 private memory**

## Web 操作台

可以启动一个仅监听本机的浏览器操作界面：

```bash
go run ./cmd/decentid web -identity alice.json -addr 127.0.0.1:8080
```

打开输出的本地 URL 后，可通过页面完成：
- 创建身份、查看公开 signed state、导出 verifier 可用 state
- 添加 public / private memory，并显式解密查看 private memory
- 添加 / 撤销 device，rotate root
- challenge → respond → verify
- issue / verify / attach attestation
- publish / resolve P2P public state

安全边界：
- Web 操作台默认拒绝非 loopback 绑定和非 localhost Host
- 默认 API 不返回 `localKeys` 或私钥字节
- private memory 只有用户点击 reveal 时才显示明文
- publish 仍只发布 signed identity state、public memory 和可选 attached attestation，不发布 private memory

## CLI 命令速查

- `web`（启动本地操作台）
- `version`
- `create`
- `show`
- `export-state`
- `keys`
- `add-memory`
- `show-memory`
- `add-device`
- `revoke-device`
- `rotate-root`
- `challenge`
- `respond`
- `verify`
- `issue-attestation`
- `verify-attestation`
- `attach-attestation`
- `publish`
- `resolve`

## 生成文件说明

### `alice.json`

本地身份文件，包含：
- identity document
- identity events
- local keyring
- preferred key IDs

注意：
- 当前原型仍把私钥明文保存在本地 JSON 中
- 这是为了原型验证，不是生产做法
- 不要把这些文件提交到公开仓库，也不要发给验证方

### `alice-state.json`

通过 `export-state` 导出的公开签名身份状态，包含：
- identity document
- identity events

说明：
- 不包含 `localKeys` 或私钥
- 验证方可用它先回放验证身份状态，再验证 challenge response

### `<memoryCID>.json`

memory object 文件。

public object 典型字段：
- `cid`
- `type`
- `createdAt`
- `contentHash`
- `payload`
- `visibility`
- `signature`

private object 典型字段：
- `cid`
- `type`
- `createdAt`
- `contentHash`
- `ciphertext`
- `encryption`
- `visibility`
- `signature`

### `<manifestCID>.json`

memory manifest 文件，包含：
- `cid`
- `items`
- `rootHash`
- `visibility`
- `signature`

### `<attestationCID>.json`

attestation 对象文件，包含：
- `cid`
- `issuerId`
- `issuerKeyId`
- `subjectId`
- `claimType`
- `claimPayload`
- `issuedAt`
- `validFrom`
- `validTo`
- `evidenceRef`
- `signature`

## 验证

```bash
gofmt -w ./cmd ./internal ./pkg
go test ./...
go vet ./...
```

当前测试已覆盖：
- DID 唯一与稳定
- replay-based state verification
- root rotation 后 DID 保持不变
- revoked device 无法继续用于 challenge 签名
- private memory 不暴露明文且可本地解密
- attestation 签名与过期校验
- P2P 远端 state / object 拉取

## 已知限制

- 这是原型，不是生产系统
- 私钥仍以本地明文 JSON 保存
- private memory 目前只支持 owner-self decrypt
- attestation 目前只做对象级签名验证，不做更高层 trust policy
- `resolve` CLI 当前只直接输出 identity state，不自动追取关联对象
- object store 目前是进程内内存缓存，不是持久化存储

## 下一步建议

1. shared / multi-recipient private memory
2. 持久化 object store
3. provider-based object discovery
4. long-running node process
5. 更高层 attestation trust policy
6. 生产级本地密钥保护
