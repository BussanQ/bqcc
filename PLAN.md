# PLAN

本文件把原先混入 README 的“实现计划 / 验收清单 / 约束说明”单独整理出来，作为第二版的实现记录与验收文档。

> 当前仓库代码已经实现了这里描述的第二版范围；本文件保留为架构说明和验收基线。

## Context

第一版原型已经完成：
- Go 模块
- DID 生成
- 签名事件链
- public memory
- challenge-response
- 最小 libp2p 解析

第二版目标是补齐三块真实能力：
- key rotation + device add/revoke
- attestation 签发 / 验证 / 附着
- 私有 memory 加密

第二版的关键不是继续堆字段，而是先修正身份验证语义：
当前 `VerifyState` 不能依赖最终 `IdentityDocument` 来解析所有历史事件的 signer；只要引入 key revoke / root rotate，这种做法就会把“当时合法、后来失效”的历史签名误判为无效。

因此第二版必须先把身份验证改为 **按事件回放（replay）构建状态**，再在此基础上叠加 key lifecycle、attestation 和 private memory。

## Non-negotiable constraints

- DID 仍然稳定为首次创建时的 `did:p2p:<hash(rootPublicKey)>`
- root rotate 表示身份连续性，不表示 DID 重算
- private memory 必须是真加密，不能只是 `visibility=private`
- attestation 作为独立对象按引用附着，不直接内嵌进 identity document
- 不得回退到“最终 document 校验全部历史事件”的验证方式

## Workstreams

### 1. Replay-based identity verification

目标：把状态验证从“最终 document 校验”改成“事件回放校验”。

做法：
1. 从 `CreateIdentity` 事件初始化工作态 document
2. 按顺序逐条事件：
   - 检查 `PrevEventID`
   - 用**当前工作态**里当时有效的 key 解析 signer
   - 验签
   - 应用事件到工作态 document
3. 最后把回放得到的 document 与 `SignedIdentityState.Document` 比对

关键文件：
- `internal/identity/events.go`
- `pkg/types/identity.go`

### 2. Local keyring

目标：把本地身份文件从“双私钥快照”升级为多 key keyring。

本地文件需要保存：
- `Document`
- `Events`
- `LocalKeys[]`
- `PreferredRootKeyID`
- `PreferredDeviceKeyID`
- `PreferredEncryptionKeyID`

`LocalKeys[]` 至少包含：
- `KeyID`
- `Type`
- `Role`
- `PrivateKey`
- `Label`

关键文件：
- `internal/identity/keys.go`
- `pkg/types/identity.go`

### 3. Key lifecycle

目标：补齐 device / root 的管理能力。

需要支持：
- `AddDevice(...)`
- `RevokeDevice(...)`
- `RotateRoot(...)`
- `AddPrivateMemoryRoot(...)`
- `AttachAttestationRef(...)`

统一规则：
- 管理类事件要求当前 active root key 签名
- `RotateRoot` 由旧 root 签名，然后把 `Document.RootKeyID` 切到新 root
- 旧 root 保留在 key 集合里，但标记 `RevokedAt`
- DID 不变，只更新 root key 控制权

CLI 命令：
- `add-device`
- `revoke-device`
- `rotate-root`
- `keys`

同时修正 auth：
- `SignChallenge` 不能继续无脑使用固定 device 私钥
- 必须按 `signerKeyID` 从本地 keyring 选择设备私钥
- revoked device key 不允许继续参与 challenge 签名

关键文件：
- `internal/identity/events.go`
- `internal/identity/keys.go`
- `internal/auth/challenge.go`
- `cmd/node/main.go`

### 4. Attestation flow

目标：把 attestation 做成独立对象，并支持验证与附着。

规则：
- attestation 不直接塞进 event payload 或 identity document 正文
- 先生成独立 attestation object
- issuer 用 active root key 签名
- subject 再通过 `AttachAttestation` 事件把 attestation CID 引到自己的 identity 上

第二版只做 **public attestation**，不做私密背书。

attestation 至少包含：
- `CID`
- `Version`
- `IssuerID`
- `IssuerKeyID`
- `SubjectID`
- `ClaimType`
- `ClaimPayload`
- `IssuedAt`
- `ValidFrom`
- `ValidTo`
- `EvidenceRef`
- `Signature`

CLI 命令：
- `issue-attestation`
- `verify-attestation`
- `attach-attestation`

关键文件：
- `pkg/types/identity.go`
- `internal/attestation/attestation.go`
- `internal/identity/events.go`
- `internal/p2p/resolver.go`
- `cmd/node/main.go`

### 5. Private memory encryption

目标：第二版只做“自己可解密”的真实加密 memory。

范围：
- 支持真正加密
- 支持 `PrivateMemoryRoot`
- 暂不实现多 recipient shared memory 分发
- `shared` 枚举先保留，不进入第二版命令流

建议实现：
- 为身份增加一把专用 encryption key（`x25519`）
- private memory 创建时：
  1. 组装明文 memory payload
  2. 使用 AEAD（AES-GCM）加密
  3. 用 owner encryption public key 做密钥协商
  4. 在 `MemoryObject` 中仅写 `Ciphertext` 与加密元数据，不写明文 `Payload`
- `add-memory -visibility private` 更新 `IdentityDocument.PrivateMemoryRoot`
- `publish` 默认不自动发布 private memory object / manifest

关键文件：
- `pkg/types/identity.go`
- `internal/crypto/crypto.go`
- `internal/memory/objects.go`
- `internal/identity/events.go`
- `cmd/node/main.go`

### 6. Publish / resolve scope

目标：扩展 publish / resolve，但保持 transport 层“按 CID 传原始对象”不变。

规则：
- 继续发布 public memory manifest 与 item
- 可选发布 `AttestationRefs` 指向的 attestation 对象
- 默认不发布 private memory object / manifest
- resolver 层继续保持通用字节存取
- 语义决策放在 CLI / publish helper 上

关键文件：
- `internal/p2p/resolver.go`
- `cmd/node/main.go`

## Critical files

按优先级：
- `pkg/types/identity.go`
- `internal/identity/events.go`
- `internal/identity/keys.go`
- `internal/auth/challenge.go`
- `internal/memory/objects.go`
- `internal/crypto/crypto.go`
- `internal/p2p/resolver.go`
- `cmd/node/main.go`
- `internal/attestation/attestation.go`

## Acceptance checklist

### 1. 单元 / 包级测试

应覆盖：
- identity replay 验证
- add device 后 challenge 可用
- revoke device 后旧 key 失效
- rotate root 后 DID 不变
- rotate / revoke 后历史事件链仍可回放验证
- `SignChallenge` 会选对 signer key
- revoked device 无法继续签名
- private memory 不暴露明文 payload
- 本地可解密，非持有者不可解密
- attestation 签名与有效期校验
- public identity + attestation object 可发布 / 解析
- private object 不会被默认发布

### 2. CLI 端到端

应至少跑通：
1. 创建身份 A
2. `add-device` 增加第二设备 key
3. 用新 device key 完成 challenge-response
4. `revoke-device` 后旧 key challenge 失败
5. `rotate-root` 后 DID 保持不变，`show` 可见新 root key 生效
6. 创建 private memory，确认本地文件中不再出现明文 payload，且能通过 CLI 解密
7. 由身份 B 给身份 A 签发 attestation，A attach 后 `show` 能看到 attestation ref
8. `publish` 后另一节点能解析 A 的 identity state，并按需拉取 public attestation object

### 3. Go 验证命令

```bash
gofmt -w ./cmd ./internal ./pkg
go test ./...
go vet ./...
```

必要时使用：

```bash
go run ./cmd/node ...
```

## What not to do in V2

- 不要继续沿用“最终 document 校验全部历史事件”的 `VerifyState`
- 不要在 root rotate 后重算 DID
- 不要把 private memory 做成 `visibility=private` 的明文对象
- 不要让 `SignChallenge` 继续忽略 `signerKeyID`
- 不要把 attestation 内嵌进 document / event 正文
- 不要默认发布 private memory 到 P2P object store
