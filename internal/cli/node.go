package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/decentid/internal/app"
	"github.com/example/decentid/internal/attestation"
	"github.com/example/decentid/internal/auth"
	"github.com/example/decentid/internal/identity"
	"github.com/example/decentid/internal/memory"
	"github.com/example/decentid/internal/p2p"
	"github.com/example/decentid/internal/storage"
	"github.com/example/decentid/pkg/types"
	"github.com/libp2p/go-libp2p/core/peer"
)

// RunNode dispatches a node subcommand. args is the argument slice starting
// with the subcommand name (e.g. ["create", "-name", "alice"]).
func RunNode(args []string) {
	if len(args) < 1 {
		Usage()
		os.Exit(1)
	}

	switch args[0] {
	case "create":
		runCreate(args[1:])
	case "add-memory":
		runAddMemory(args[1:])
	case "show-memory":
		runShowMemory(args[1:])
	case "show":
		runShow(args[1:])
	case "export-state":
		runExportState(args[1:])
	case "keys":
		runKeys(args[1:])
	case "add-device":
		runAddDevice(args[1:])
	case "revoke-device":
		runRevokeDevice(args[1:])
	case "rotate-root":
		runRotateRoot(args[1:])
	case "issue-attestation":
		runIssueAttestation(args[1:])
	case "verify-attestation":
		runVerifyAttestation(args[1:])
	case "attach-attestation":
		runAttachAttestation(args[1:])
	case "challenge":
		runChallenge(args[1:])
	case "respond":
		runRespond(args[1:])
	case "verify":
		runVerify(args[1:])
	case "publish":
		runPublish(args[1:])
	case "resolve":
		runResolve(args[1:])
	default:
		Usage()
		os.Exit(1)
	}
}

// Usage prints the safe primary workflow before the advanced command list.
func Usage() {
	fmt.Println("DecentID：身份是一把密钥，历史是一条签名链，登录是一次签名。")
	fmt.Println()
	fmt.Println("安全上手：")
	fmt.Println("  decentid create -name Alice -out identity.json")
	fmt.Println("  decentid show -identity identity.json")
	fmt.Println("  decentid add-memory -identity identity.json -payload 'hello'")
	fmt.Println("  decentid export-state -identity identity.json -out identity-state.json")
	fmt.Println("  decentid web -identity identity.json")
	fmt.Println()
	fmt.Println("identity.json 是包含私钥的本地钥匙串，绝不外发；对外只分享公开名片 identity-state.json。")
	fmt.Println()
	fmt.Println("命令：")
	fmt.Println("  web | version | create | show | export-state | keys")
	fmt.Println("  add-memory | show-memory")
	fmt.Println("  add-device | revoke-device | rotate-root")
	fmt.Println("  issue-attestation | verify-attestation | attach-attestation")
	fmt.Println("  challenge | respond | verify")
	fmt.Println("  publish | resolve")
}

func runCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	name := fs.String("name", "", "display name")
	out := fs.String("out", "identity.json", "output file")
	force := fs.Bool("force", false, "replace an existing identity file (dangerous)")
	fs.Parse(args)

	result, err := app.NewService(*out).CreateIdentity(*name, *out, *force)
	must(err)
	fmt.Printf("created %s\n", result.Summary.DID)
	fmt.Printf("local keyring: %s (do not share)\n", result.Summary.IdentityPath)
}

func runAddMemory(args []string) {
	fs := flag.NewFlagSet("add-memory", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	kind := fs.String("type", "note", "memory type")
	payload := fs.String("payload", "", "memory payload")
	visibility := fs.String("visibility", string(types.VisibilityPublic), "visibility: public or private")
	fs.Parse(args)

	result, err := app.NewService(*file).AddMemory(*kind, *payload, types.Visibility(*visibility))
	must(err)
	fmt.Printf("memory %s\nmanifest %s (%d current items)\n", result.ObjectCID, result.ManifestCID, len(result.Manifest.Items))
}

func runShowMemory(args []string) {
	fs := flag.NewFlagSet("show-memory", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	memoryFile := fs.String("memory", "", "memory object file")
	fs.Parse(args)

	id := loadIdentity(*file)
	var obj types.MemoryObject
	readJSON(*memoryFile, &obj)
	if obj.Visibility != types.VisibilityPrivate {
		printJSON(obj)
		return
	}
	priv, err := id.PreferredEncryptionPrivateKey()
	must(err)
	plaintext, err := memory.DecryptObject(obj, priv)
	must(err)
	fmt.Println(plaintext)
}

func runShow(args []string) {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	fs.Parse(args)

	summary, err := app.NewService(*file).Summary()
	must(err)
	printJSON(summary)
}

func runExportState(args []string) {
	fs := flag.NewFlagSet("export-state", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	out := fs.String("out", "identity-state.json", "output public state file")
	fs.Parse(args)

	result, err := app.NewService(*file).ExportState(*out)
	must(err)
	fmt.Printf("public identity card written to %s\n", result.OutFile)
}

func runKeys(args []string) {
	fs := flag.NewFlagSet("keys", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	fs.Parse(args)

	summary, err := app.NewService(*file).Summary()
	must(err)
	printJSON(map[string]interface{}{
		"rootKeyId":                summary.RootKeyID,
		"preferredRootKeyId":       summary.PreferredRootKeyID,
		"preferredDeviceKeyId":     summary.PreferredDeviceKeyID,
		"preferredEncryptionKeyId": summary.PreferredEncryptionKeyID,
		"keys":                     summary.Keys,
		"warning":                  "private key bytes are hidden; the identity file is the local keyring and must not be shared",
	})
}

func runAddDevice(args []string) {
	fs := flag.NewFlagSet("add-device", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	label := fs.String("label", "device", "device label")
	fs.Parse(args)

	id := loadIdentity(*file)
	record, err := id.AddDevice(*label)
	must(err)
	saveIdentity(*file, id)
	printJSON(record)
}

func runRevokeDevice(args []string) {
	fs := flag.NewFlagSet("revoke-device", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	keyID := fs.String("key-id", "", "device key id")
	reason := fs.String("reason", "", "revoke reason")
	fs.Parse(args)

	id := loadIdentity(*file)
	must(id.RevokeDevice(*keyID, *reason))
	saveIdentity(*file, id)
	fmt.Printf("revoked %s\n", *keyID)
}

func runRotateRoot(args []string) {
	fs := flag.NewFlagSet("rotate-root", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	label := fs.String("label", "rotated-root", "root key label")
	fs.Parse(args)

	id := loadIdentity(*file)
	record, err := id.RotateRoot(*label)
	must(err)
	saveIdentity(*file, id)
	printJSON(record)
}

func runIssueAttestation(args []string) {
	fs := flag.NewFlagSet("issue-attestation", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "issuer identity file")
	subject := fs.String("subject", "", "subject did")
	claimType := fs.String("claim-type", "known", "claim type")
	claimValue := fs.String("claim-value", "", "claim value")
	evidenceRef := fs.String("evidence-ref", "", "evidence ref")
	validFor := fs.Duration("valid-for", 24*time.Hour, "valid duration")
	out := fs.String("out", "attestation.json", "output file")
	fs.Parse(args)

	id := loadIdentity(*file)
	claimPayload := map[string]interface{}{"value": *claimValue}
	att, err := attestation.New(id.Document.ID, id.Document.RootKeyID, *subject, *claimType, claimPayload, *validFor, *evidenceRef)
	must(err)
	rootPriv, err := id.PreferredRootPrivateKey()
	must(err)
	must(attestation.Sign(&att, rootPriv))
	writeJSON(*out, att)
	fmt.Printf("attestation %s\n", att.CID)
}

func runVerifyAttestation(args []string) {
	fs := flag.NewFlagSet("verify-attestation", flag.ExitOnError)
	issuerStateFile := fs.String("issuer-state", "", "issuer public identity state file")
	issuerFile := fs.String("issuer", "identity.json", "deprecated issuer local identity file")
	attFile := fs.String("attestation", "attestation.json", "attestation file")
	fs.Parse(args)

	var att types.Attestation
	readJSON(*attFile, &att)
	var state types.SignedIdentityState
	if *issuerStateFile != "" {
		state = loadSignedState(*issuerStateFile)
	} else {
		fmt.Fprintln(os.Stderr, "warning: -issuer is deprecated; export and pass the issuer's public state with -issuer-state")
		state = loadIdentity(*issuerFile).SignedState()
	}
	printJSON(app.VerifyAttestationWithState(state, att))
}

func runAttachAttestation(args []string) {
	fs := flag.NewFlagSet("attach-attestation", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	attFile := fs.String("attestation", "attestation.json", "attestation file")
	fs.Parse(args)

	id := loadIdentity(*file)
	var att types.Attestation
	readJSON(*attFile, &att)
	cidPath := filepath.Join(filepath.Dir(*file), att.CID+".json")
	writeJSON(cidPath, att)
	must(id.AttachAttestationRef(att.CID))
	saveIdentity(*file, id)
	fmt.Printf("attached %s\n", att.CID)
}

func runChallenge(args []string) {
	fs := flag.NewFlagSet("challenge", flag.ExitOnError)
	identityID := fs.String("id", "", "identity id")
	out := fs.String("out", "challenge.json", "output file")
	ttl := fs.Duration("ttl", 5*time.Minute, "challenge ttl")
	fs.Parse(args)

	challenge, err := auth.NewChallenge(*identityID, *ttl)
	must(err)
	writeJSON(*out, challenge)
	fmt.Printf("challenge written to %s\n", *out)
}

func runRespond(args []string) {
	fs := flag.NewFlagSet("respond", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	challengeFile := fs.String("challenge", "challenge.json", "challenge file")
	out := fs.String("out", "response.json", "output file")
	signerKeyID := fs.String("signer-key-id", "", "device signer key id")
	fs.Parse(args)

	id := loadIdentity(*file)
	var challenge types.Challenge
	readJSON(*challengeFile, &challenge)
	response, err := auth.SignChallenge(challenge, *signerKeyID, id)
	must(err)
	writeJSON(*out, response)
	fmt.Printf("response written to %s\n", *out)
}

func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	stateFile := fs.String("state", "", "public signed identity state file")
	identityFile := fs.String("identity", "", "deprecated local identity file")
	responseFile := fs.String("response", "response.json", "response file")
	fs.Parse(args)

	var response types.ChallengeResponse
	readJSON(*responseFile, &response)

	if *stateFile != "" {
		state := loadSignedState(*stateFile)
		fmt.Println(auth.VerifyChallenge(response, state.Document))
		return
	}
	if *identityFile != "" {
		fmt.Fprintln(os.Stderr, "warning: -identity is deprecated for verify; use -state with exported public state")
		id := loadIdentity(*identityFile)
		fmt.Println(auth.VerifyChallenge(response, id.Document))
		return
	}
	must(fmt.Errorf("verify requires -state <public-state.json>; -identity is deprecated for local-only verification"))
}

func runPublish(args []string) {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	listen := fs.String("listen", "/ip4/127.0.0.1/tcp/0", "listen multiaddr")
	wait := fs.Duration("wait", 30*time.Second, "serve duration")
	includeAttestations := fs.Bool("include-attestations", true, "publish attached attestations")
	fs.Parse(args)

	id := loadIdentity(*file)
	ctx, cancel := context.WithTimeout(context.Background(), *wait)
	defer cancel()
	resolver, err := p2p.NewResolver(ctx, *listen)
	must(err)
	defer resolver.Close()

	state := id.SignedState()
	_, err = storage.StoreReferencedObjects(resolver, *file, state, *includeAttestations)
	must(err)
	must(resolver.PublishState(ctx, state))
	fmt.Println(strings.Join(resolver.AddrStrings(), "\n"))
	<-ctx.Done()
}

func runResolve(args []string) {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	listen := fs.String("listen", "/ip4/127.0.0.1/tcp/0", "listen multiaddr")
	peerAddr := fs.String("peer", "", "remote peer multiaddr")
	identityID := fs.String("id", "", "identity id")
	fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resolver, err := p2p.NewResolver(ctx, *listen)
	must(err)
	defer resolver.Close()
	must(resolver.DialPeer(ctx, *peerAddr))
	info, err := peer.AddrInfoFromString(*peerAddr)
	must(err)
	state, err := resolver.ResolveRemote(ctx, info.ID, *identityID)
	must(err)
	must(identity.VerifyState(state))
	printJSON(state)
}

func loadIdentity(path string) *identity.Identity {
	id, err := storage.LoadIdentity(path)
	must(err)
	return id
}

func loadSignedState(path string) types.SignedIdentityState {
	data, err := os.ReadFile(path)
	must(err)
	state, err := identity.UnmarshalSignedState(data)
	must(err)
	must(identity.VerifyState(state))
	return state
}

func saveIdentity(path string, id *identity.Identity) {
	must(storage.SaveIdentity(path, id))
}

func readJSON(path string, out interface{}) {
	must(storage.ReadJSON(path, out))
}

func writeJSON(path string, value interface{}) {
	must(storage.WriteJSON(path, value))
}

func printJSON(value interface{}) {
	data, err := json.MarshalIndent(value, "", "  ")
	must(err)
	fmt.Println(string(data))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
