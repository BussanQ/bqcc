package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/decentid/internal/attestation"
	"github.com/example/decentid/internal/auth"
	"github.com/example/decentid/internal/identity"
	"github.com/example/decentid/internal/memory"
	"github.com/example/decentid/internal/p2p"
	"github.com/example/decentid/pkg/types"
	"github.com/libp2p/go-libp2p/core/peer"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "create":
		runCreate(os.Args[2:])
	case "add-memory":
		runAddMemory(os.Args[2:])
	case "show-memory":
		runShowMemory(os.Args[2:])
	case "show":
		runShow(os.Args[2:])
	case "export-state":
		runExportState(os.Args[2:])
	case "keys":
		runKeys(os.Args[2:])
	case "add-device":
		runAddDevice(os.Args[2:])
	case "revoke-device":
		runRevokeDevice(os.Args[2:])
	case "rotate-root":
		runRotateRoot(os.Args[2:])
	case "issue-attestation":
		runIssueAttestation(os.Args[2:])
	case "verify-attestation":
		runVerifyAttestation(os.Args[2:])
	case "attach-attestation":
		runAttachAttestation(os.Args[2:])
	case "challenge":
		runChallenge(os.Args[2:])
	case "respond":
		runRespond(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "publish":
		runPublish(os.Args[2:])
	case "resolve":
		runResolve(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("decentid node commands: create | add-memory | show-memory | show | export-state | keys | add-device | revoke-device | rotate-root | issue-attestation | verify-attestation | attach-attestation | challenge | respond | verify | publish | resolve")
}

func runCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	name := fs.String("name", "", "display name")
	out := fs.String("out", "identity.json", "output file")
	fs.Parse(args)

	id, err := identity.New(*name)
	must(err)
	data, err := identity.MarshalLocal(id.ExportLocal())
	must(err)
	must(os.WriteFile(*out, data, 0o600))
	fmt.Printf("created %s\n", id.Document.ID)
}

func runAddMemory(args []string) {
	fs := flag.NewFlagSet("add-memory", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	kind := fs.String("type", "note", "memory type")
	payload := fs.String("payload", "", "memory payload")
	visibility := fs.String("visibility", string(types.VisibilityPublic), "visibility")
	fs.Parse(args)

	id := loadIdentity(*file)
	rootPriv, err := id.PreferredRootPrivateKey()
	must(err)

	var obj types.MemoryObject
	if types.Visibility(*visibility) == types.VisibilityPrivate {
		encryptionKeyID := id.EncryptionKeyID()
		if encryptionKeyID == "" {
			must(fmt.Errorf("no active encryption key"))
		}
		publicKey, err := identity.ResolveEncryptionPublicKey(id.Document, encryptionKeyID)
		must(err)
		obj, err = memory.NewPrivateObject(*kind, *payload, encryptionKeyID, publicKey, nil, nil)
		must(err)
	} else {
		obj, err = memory.NewObject(*kind, *payload, types.Visibility(*visibility), nil, nil)
		must(err)
	}
	must(memory.SignObject(&obj, rootPriv))
	manifest, err := memory.NewManifest(types.Visibility(*visibility), []types.MemoryObject{obj})
	must(err)
	must(memory.SignManifest(&manifest, rootPriv))
	if types.Visibility(*visibility) == types.VisibilityPrivate {
		must(id.AddPrivateMemoryRoot(manifest.CID))
	} else {
		must(id.AddPublicMemoryRoot(manifest.CID))
	}
	saveIdentity(*file, id)

	memoryFile := filepath.Join(filepath.Dir(*file), obj.CID+".json")
	manifestFile := filepath.Join(filepath.Dir(*file), manifest.CID+".json")
	writeJSON(memoryFile, obj)
	writeJSON(manifestFile, manifest)
	fmt.Printf("memory %s\nmanifest %s\n", obj.CID, manifest.CID)
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

	id := loadIdentity(*file)
	printJSON(id.ExportLocal())
}

func runExportState(args []string) {
	fs := flag.NewFlagSet("export-state", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	out := fs.String("out", "identity-state.json", "output public state file")
	fs.Parse(args)

	id := loadIdentity(*file)
	writeJSON(*out, id.SignedState())
	fmt.Printf("state written to %s\n", *out)
}

func runKeys(args []string) {
	fs := flag.NewFlagSet("keys", flag.ExitOnError)
	file := fs.String("identity", "identity.json", "identity file")
	fs.Parse(args)

	id := loadIdentity(*file)
	printJSON(map[string]interface{}{
		"rootKeyId":             id.Document.RootKeyID,
		"preferredRootKeyId":    id.PreferredRootKeyID,
		"preferredDeviceKeyId":  id.PreferredDeviceKeyID,
		"preferredEncryptKeyId": id.PreferredEncryptionKeyID,
		"activeKeys":            id.Document.ActiveKeys,
		"localKeys":             id.ExportLocal().LocalKeys,
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
	issuerFile := fs.String("issuer", "identity.json", "issuer identity file")
	attFile := fs.String("attestation", "attestation.json", "attestation file")
	fs.Parse(args)

	issuer := loadIdentity(*issuerFile)
	var att types.Attestation
	readJSON(*attFile, &att)
	pub, err := identity.ResolveKey(issuer.Document, att.IssuerKeyID)
	must(err)
	fmt.Println(attestation.Verify(att, pub))
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
	must(resolver.PublishState(ctx, state))
	storeReferencedObjects(resolver, *file, state, *includeAttestations)
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
	printJSON(state)
}

func storeReferencedObjects(resolver *p2p.Resolver, identityFile string, state types.SignedIdentityState, includeAttestations bool) {
	baseDir := filepath.Dir(identityFile)
	if state.Document.PublicMemoryRoot != "" {
		manifestFile := filepath.Join(baseDir, state.Document.PublicMemoryRoot+".json")
		if data, err := os.ReadFile(manifestFile); err == nil {
			resolver.StoreObject(state.Document.PublicMemoryRoot, data)
			var manifest types.MemoryManifest
			if err := json.Unmarshal(data, &manifest); err == nil {
				for _, cid := range manifest.Items {
					memoryFile := filepath.Join(baseDir, cid+".json")
					if payload, err := os.ReadFile(memoryFile); err == nil {
						resolver.StoreObject(cid, payload)
					}
				}
			}
		}
	}
	if includeAttestations {
		for _, cid := range state.Document.AttestationRefs {
			attFile := filepath.Join(baseDir, cid+".json")
			if data, err := os.ReadFile(attFile); err == nil {
				resolver.StoreObject(cid, data)
			}
		}
	}
}

func loadIdentity(path string) *identity.Identity {
	data, err := os.ReadFile(path)
	must(err)
	local, err := identity.UnmarshalLocal(data)
	must(err)
	id, err := identity.FromLocal(local)
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
	data, err := identity.MarshalLocal(id.ExportLocal())
	must(err)
	must(os.WriteFile(path, data, 0o600))
}

func readJSON(path string, out interface{}) {
	data, err := os.ReadFile(path)
	must(err)
	must(json.Unmarshal(data, out))
}

func writeJSON(path string, value interface{}) {
	data, err := json.MarshalIndent(value, "", "  ")
	must(err)
	must(os.WriteFile(path, data, 0o600))
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
