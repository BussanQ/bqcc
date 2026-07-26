# decentid CLI 使用说明

`decentid` 是一个去中心化身份协议原型。先记住 3 个概念：**身份=密钥、连续性=签名变更链、登录=签名**。术语说明见 [`概念模型.md`](./概念模型.md)。

## 1. 准备与帮助

需要 Go 1.24+。在仓库根目录可直接运行：

```bash
go run ./cmd/decentid help
go run ./cmd/decentid version
```

也可先构建单文件程序：

```bash
go build -o decentid ./cmd/decentid
```

后文的 `decentid` 可替换为 `go run ./cmd/decentid`。

## 2. 最短安全流程

```bash
decentid create -name Alice -out identity.json
decentid show -identity identity.json
decentid add-memory -identity identity.json -payload "hello"
decentid export-state -identity identity.json -out identity-state.json
decentid web -identity identity.json -addr 127.0.0.1:8080
```

- `identity.json` 是包含私钥的本地**钥匙串**，绝不外发。
- `identity-state.json` 是不含私钥的**公开名片**，可交给验证方。
- `show` 和 `keys` 只输出安全摘要与公开 key，不再打印 `localKeys/privateKey`。

## 3. 创建与查看身份

```bash
decentid create -name Alice -out identity.json
decentid show -identity identity.json
decentid keys -identity identity.json
```

若目标文件已存在，`create` 默认失败，避免覆盖钥匙串。只有明确要替换时才使用：

```bash
decentid create -name Bob -out identity.json -force
```

`-force` 会创建新的初始主控密钥和新的身份码。执行前应先导出完整备份。

导出给验证方的公开名片：

```bash
decentid export-state -identity identity.json -out identity-state.json
```

## 4. 内容

添加公开内容：

```bash
decentid add-memory -identity identity.json -type note -payload "hello public"
```

添加只有自己能看的加密内容：

```bash
decentid add-memory -identity identity.json -type note -payload "secret" -visibility private
```

合法 visibility 只有 `public` 和 `private`。每次新增内容都会保留当前同类目录中的已有 items，并生成新的累积 manifest；输出会显示当前 item 数量。

查看对象：

```bash
decentid show-memory -identity identity.json -memory <memoryCID>.json
```

- public：输出对象 JSON。
- private：使用本地加密私钥解密并输出用户 payload。

旧版本地单项内容的检测与整理目前在默认 Web 操作台的“内容”页提供。整理只追加新变更记录，不改旧对象或身份码。

## 5. 设备与主控密钥

```bash
decentid add-device -identity identity.json -label backup-signer
decentid keys -identity identity.json
decentid revoke-device -identity identity.json -key-id <deviceKeyId> -reason "lost"
decentid rotate-root -identity identity.json -label rotated-root
```

注意：`add-device` 当前是在同一个本地钥匙串中生成额外设备密钥，不会自动把密钥发送到另一台手机或电脑。root rotation 只改变控制密钥，身份码保持不变。

## 6. challenge-response 登录验证

验证方生成题目：

```bash
decentid challenge -id "did:p2p:..." -ttl 5m -out challenge.json
```

身份持有者签名作答：

```bash
decentid respond -identity identity.json -challenge challenge.json -out response.json
```

可显式指定 active device key：

```bash
decentid respond -identity identity.json -challenge challenge.json -signer-key-id <deviceKeyId> -out response.json
```

验证方使用公开名片验签：

```bash
decentid verify -state identity-state.json -response response.json
```

过期题目、被撤销设备或无法通过 replay 验证的公开状态都会失败。`verify -identity` 只为旧本机流程兼容，新的验证方流程应始终使用 `-state`。

## 7. 他人背书

签发 standalone attestation：

```bash
decentid issue-attestation -identity issuer.json -subject "did:p2p:..." -claim-type known -claim-value Alice -out attestation.json
```

issuer 先导出公开名片，验证方不需要 issuer 的私有钥匙串：

```bash
decentid export-state -identity issuer.json -out issuer-state.json
decentid verify-attestation -issuer-state issuer-state.json -attestation attestation.json
```

旧的 `-issuer issuer.json` 仍临时兼容，但会输出弃用警告。

被背书者按 CID 引用附着：

```bash
decentid attach-attestation -identity identity.json -attestation attestation.json
```

## 8. P2P 发布与取回

终端 A：

```bash
decentid publish -identity identity.json -wait 10m
```

默认发布：

- 已通过 replay 验证的 signed identity state；
- 当前 public memory manifest 和全部成员对象；
- 已附着的 standalone attestation（可用 `-include-attestations=false` 关闭）。

发布前会校验对象 CID、签名和引用完整性；private manifest/object 永远不进入发布集合。

终端 B：

```bash
decentid resolve -peer "<peer-multiaddr>" -id "did:p2p:..."
```

CLI 会在输出前对远端 `SignedIdentityState` 做 replay 验证。当前 `resolve` 仍只输出身份状态，不自动持久化关联对象。

## 9. 完整加密备份

备份/恢复目前由本机 Web 操作台提供：

```bash
decentid web -identity identity.json -addr 127.0.0.1:8080
```

打开“备份”页：

- v2 备份包含钥匙串、当前公开/私有内容目录和对象、已附着他人背书；
- bundle 使用 scrypt + AES-256-GCM 加密；
- 导入前校验 identity replay、对象 CID 和引用闭包；
- v1 旧版仅身份备份仍可导入，但会明确警告没有恢复内容；
- 若检测到旧版本地内容未纳入当前目录，会先要求在“内容”页整理，避免静默遗漏。

## 10. 命令速查

```text
web | version | create | show | export-state | keys
add-memory | show-memory
add-device | revoke-device | rotate-root
challenge | respond | verify
issue-attestation | verify-attestation | attach-attestation
publish | resolve
```

## 11. 开发验证

```bash
gofmt -w ./cmd ./internal ./pkg
go test ./...
go vet ./...
```
