# decentid 使用说明

本文档面向直接使用当前 CLI 原型的开发者，覆盖从创建身份到 memory、device、challenge-response、attestation、P2P publish/resolve 的完整流程。

如需项目背景和协议说明，先看仓库根目录下的 `README.md`；实现范围和验收基线见 `PLAN.md`。
概念不清先看 [`概念模型.md`](./概念模型.md)：核心只有 3 个，并附行话→大白话术语对照表。

## 1. 环境准备

### 依赖

- Go 1.24+

### 安装依赖

在仓库根目录执行：

```bash
go mod tidy
```

### 建议的本地文件目录

当前仓库已经把身份相关 JSON 放到 `bq/` 目录下，后续命令都建议沿用这个目录：

```bash
mkdir -p bq
```

> `bq/` 里的文件通常包含本地私钥或认证材料，不要提交到公开仓库。

## 2. CLI 命令总览

当前支持的命令：

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

## 3. 创建身份

创建一个新身份：

```bash
go run ./cmd/decentid create -name alice -out bq/identity.json
```

成功后会输出类似：

```text
created did:p2p:...
```

生成的 `bq/identity.json` 是本地身份文件，里面包含：

- identity document
- identity events
- local keyring
- preferred key IDs

### 重要安全说明

`bq/identity.json` **不能公开**。

原因是它包含 `localKeys`，其中有：

- root 私钥
- device 私钥
- encryption 私钥

任何拿到这个文件的人，都可能直接控制该身份。

## 4. 查看身份内容

查看本地身份文件内容：

```bash
go run ./cmd/decentid show -identity bq/identity.json
```

这会直接打印完整的本地身份 JSON。

### 注意

`show` 输出的是 **本地身份文件**，不是脱敏后的公开视图，所以同样不要随意贴到公网、Issue、聊天记录或截图里。

如果你只是想看 key 状态，优先用下面的 `keys`。

## 5. 查看 key 状态

```bash
go run ./cmd/decentid keys -identity bq/identity.json
```

会输出：

- `rootKeyId`
- `preferredRootKeyId`
- `preferredDeviceKeyId`
- `preferredEncryptKeyId`
- `activeKeys`
- `localKeys`

这个命令常用于：

- 找当前 active root key
- 找当前默认 device key
- 找要撤销的 device key ID
- 确认 root rotate 后当前生效的 root key

## 6. 添加 memory

### 6.1 添加 public memory

```bash
go run ./cmd/decentid add-memory -identity bq/identity.json -type note -payload "hello public"
```

执行后会输出两个 CID：

```text
memory <memoryCID>
manifest <manifestCID>
```

同时会在 `bq/` 目录下生成两个文件：

- `bq/<memoryCID>.json`
- `bq/<manifestCID>.json`

并更新身份中的 public memory root。

### 6.2 添加 private memory

```bash
go run ./cmd/decentid add-memory -identity bq/identity.json -type note -payload "secret memory" -visibility private
```

这条命令会：

- 用当前 active encryption key 加密 payload
- 生成 private memory object
- 生成 private manifest
- 更新身份中的 `privateMemoryRoot`

### 6.3 查看 memory 文件

如果是 public memory，可以直接打开文件看 JSON；如果是 private memory，文件里不会保存明文 `payload`。

当前 private object 典型字段是：

- `cid`
- `type`
- `createdAt`
- `contentHash`
- `ciphertext`
- `encryption`
- `visibility`
- `signature`

### 6.4 解密查看 private memory

```bash
go run ./cmd/decentid show-memory -identity bq/identity.json -memory bq/<memoryCID>.json
```

行为说明：

- 如果目标是 public memory：直接打印对象 JSON
- 如果目标是 private memory：使用本地 encryption private key 解密，并直接输出明文 payload

## 7. 增加设备

增加一个新的 device key：

```bash
go run ./cmd/decentid add-device -identity bq/identity.json -label laptop
```

返回结果里会包含新 device key 的记录和 key ID。

建议随后执行：

```bash
go run ./cmd/decentid keys -identity bq/identity.json
```

确认：

- 新设备是否已经进入 `activeKeys`
- 本地是否保存了对应私钥

## 8. 撤销设备

先查出要撤销的设备 key ID：

```bash
go run ./cmd/decentid keys -identity bq/identity.json
```

然后执行：

```bash
go run ./cmd/decentid revoke-device -identity bq/identity.json -key-id <deviceKeyId> -reason "lost"
```

成功后会输出：

```text
revoked <deviceKeyId>
```

### 撤销后的影响

被撤销的 device key：

- 仍然会留在历史事件里
- 不会破坏历史 replay 验证
- **不能再用于 challenge-response 签名**

## 9. challenge-response 认证流程

这套认证是无中心账号、无 session 数据库的签名式验证。

### 9.1 生成 challenge

```bash
go run ./cmd/decentid challenge -id "did:p2p:..." -out bq/challenge.json
```

也可以指定有效期：

```bash
go run ./cmd/decentid challenge -id "did:p2p:..." -ttl 10m -out bq/challenge.json
```

### 9.2 用身份响应 challenge

默认使用当前 preferred device key：

```bash
go run ./cmd/decentid respond -identity bq/identity.json -challenge bq/challenge.json -out bq/response.json
```

显式指定设备 key：

```bash
go run ./cmd/decentid respond -identity bq/identity.json -challenge bq/challenge.json -signer-key-id <deviceKeyId> -out bq/response.json
```

### 9.3 导出公开身份状态

```bash
go run ./cmd/decentid export-state -identity bq/identity.json -out bq/state.json
```

`bq/identity.json` 是本地私有文件，不应该发给验证方。验证方只需要公开的 `bq/state.json`。

### 9.4 验证 response

```bash
go run ./cmd/decentid verify -state bq/state.json -response bq/response.json
```

输出为：

- `true`：验证通过
- `false`：验证失败

### 9.5 常见失败原因

- challenge 已过期
- `signer-key-id` 对应的 key 已被撤销
- 用了不是 device role 的 key
- 响应文件与 challenge 不匹配
- response 的 identity 与 `state.document.id` 不匹配
- 公开 signed state 被手工改坏，事件链验证失败

## 10. root rotate

root rotate 会更换控制身份的 active root key，但 **不会改变 DID**。

执行：

```bash
go run ./cmd/decentid rotate-root -identity bq/identity.json -label rotated-root
```

然后查看：

```bash
go run ./cmd/decentid keys -identity bq/identity.json
go run ./cmd/decentid show -identity bq/identity.json
```

你应当关注：

- `Document.ID` 是否保持不变
- `Document.RootKeyID` 是否已切到新 root
- 老 root 是否还保留在历史 key 集里

## 11. attestation 流程

attestation 是独立对象，不会直接塞进 identity document 正文里。身份上只会附着 attestation 的 CID 引用。

下面用两个身份举例：

- `bq/issuer.json`
- `bq/alice.json`

### 11.1 创建 issuer 和 subject 身份

```bash
go run ./cmd/decentid create -name issuer -out bq/issuer.json
go run ./cmd/decentid create -name alice -out bq/alice.json
```

先用 `show` 查看 `bq/alice.json` 里的 DID，记作 `<subjectDID>`。

### 11.2 签发 attestation

```bash
go run ./cmd/decentid issue-attestation \
  -identity bq/issuer.json \
  -subject "<subjectDID>" \
  -claim-type known \
  -claim-value alice \
  -out bq/attestation.json
```

可选参数：

- `-evidence-ref <ref>`
- `-valid-for 48h`

### 11.3 验证 attestation

```bash
go run ./cmd/decentid verify-attestation -issuer bq/issuer.json -attestation bq/attestation.json
```

会输出校验结果。

### 11.4 把 attestation 附着到 subject 身份

```bash
go run ./cmd/decentid attach-attestation -identity bq/alice.json -attestation bq/attestation.json
```

这一步会做两件事：

- 把 attestation 文件复制为 `bq/<attestationCID>.json`
- 往 identity event chain 里追加 attestation ref

附着后可以再执行：

```bash
go run ./cmd/decentid show -identity bq/alice.json
```

检查 `attestationRefs`。

## 12. P2P publish / resolve

### 12.1 发布身份状态

在终端 A 执行：

```bash
go run ./cmd/decentid publish -identity bq/identity.json -wait 10m
```

它会打印当前节点监听地址，例如：

```text
/ip4/127.0.0.1/tcp/12345/p2p/...
```

默认 publish 行为：

- 发布 signed identity state
- 发布 public memory manifest
- 发布 public memory objects
- 发布已附着 attestation objects
- **不会发布 private memory objects**

如果不想发布 attestation 对象：

```bash
go run ./cmd/decentid publish -identity bq/identity.json -wait 10m -include-attestations=false
```

### 12.2 从远端解析身份状态

在终端 B 执行：

```bash
go run ./cmd/decentid resolve -peer "<peerMultiaddr>" -id "did:p2p:..."
```

这会输出远端返回的 signed identity state。

### 12.3 当前 resolve 的边界

当前 `resolve` 命令：

- 会取回远端 identity state
- 不会自动把相关 memory / attestation 文件全部下载到本地目录
- 更偏向协议验证与最小链路演示

## 13. 推荐的完整演示顺序

如果你想快速跑一遍当前原型，建议按这个顺序：

### 13.1 创建身份

```bash
go run ./cmd/decentid create -name alice -out bq/identity.json
```

### 13.2 添加一条 public memory

```bash
go run ./cmd/decentid add-memory -identity bq/identity.json -type note -payload "hello public"
```

### 13.3 添加一条 private memory

```bash
go run ./cmd/decentid add-memory -identity bq/identity.json -type note -payload "secret note" -visibility private
```

### 13.4 增加一个设备

```bash
go run ./cmd/decentid add-device -identity bq/identity.json -label phone
```

### 13.5 跑 challenge-response

```bash
go run ./cmd/decentid export-state -identity bq/identity.json -out bq/state.json
go run ./cmd/decentid challenge -id "did:p2p:..." -out bq/challenge.json
go run ./cmd/decentid respond -identity bq/identity.json -challenge bq/challenge.json -out bq/response.json
go run ./cmd/decentid verify -state bq/state.json -response bq/response.json
```

### 13.6 rotate root

```bash
go run ./cmd/decentid rotate-root -identity bq/identity.json -label rotated-root
```

### 13.7 发布并远端解析

终端 A：

```bash
go run ./cmd/decentid publish -identity bq/identity.json -wait 10m
```

终端 B：

```bash
go run ./cmd/decentid resolve -peer "<peerMultiaddr>" -id "did:p2p:..."
```

## 14. 文件说明

### `bq/identity.json`

本地身份文件，包含私钥，不能公开。

### `bq/state.json`

通过 `export-state` 导出的公开 signed identity state，包含 document 和 events，不包含 `localKeys` 或私钥。验证方可以使用它验证 challenge response。

### `bq/challenge.json`

challenge 请求文件。

### `bq/response.json`

challenge-response 的签名响应文件。

### `bq/<memoryCID>.json`

memory object 文件。

- public memory：直接包含明文 payload
- private memory：包含 ciphertext 和加密元数据，不包含明文 payload

### `bq/<manifestCID>.json`

memory manifest 文件，记录当前 memory root 下的 item CID 列表。

### `bq/<attestationCID>.json`

attestation 对象文件。

## 15. 安全建议

1. 不要公开 `identity.json` 或 `show` 输出。
2. 验证方使用 `export-state` 导出的公开 state，不要索要本地身份文件。
3. 不要把 `bq/*.json` 提交到公开仓库。
4. private memory 文件虽然不含明文，但本地身份文件里有解密私钥，二者应一起保护。
5. 不要手工修改 identity JSON；事件签名和 canonical 结构很容易因此失效。
6. 做外部演示时，优先新建一个演示身份，不要直接拿长期使用的本地身份文件演示。

## 16. 当前已知限制

当前实现是原型，不是生产系统。已知限制包括：

- 本地私钥仍保存在 JSON 文件里
- private memory 目前只支持 owner-self decrypt
- `resolve` 只直接输出 identity state，不自动追取关联对象
- object store 目前不是持久化存储
- 还没有更高层 trust / reputation policy
- 还没有生产级密钥托管与恢复机制

## 17. 开发验证命令

如果你修改了代码，建议在仓库根目录执行：

```bash
gofmt -w ./cmd ./internal ./pkg
go test ./...
go vet ./...
```
