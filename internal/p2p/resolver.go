package p2p

import (
	"context"
	"errors"
	"io"
	"sync"

	libp2p "github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/example/decentid/pkg/types"
)

const (
	identityProtocol protocol.ID = "/decentid/state/1.0.0"
	objectProtocol   protocol.ID = "/decentid/object/1.0.0"
)

type Resolver struct {
	host    host.Host
	dht     *dht.IpfsDHT
	pubsub  *pubsub.PubSub
	mu      sync.RWMutex
	states  map[string]types.SignedIdentityState
	objects map[string][]byte
	topics  map[string]*pubsub.Topic
}

func NewResolver(ctx context.Context, listenAddr string) (*Resolver, error) {
	addr, err := ma.NewMultiaddr(listenAddr)
	if err != nil {
		return nil, err
	}
	h, err := libp2p.New(libp2p.ListenAddrs(addr))
	if err != nil {
		return nil, err
	}
	kdht, err := dht.New(ctx, h)
	if err != nil {
		return nil, err
	}
	if err := kdht.Bootstrap(ctx); err != nil {
		return nil, err
	}
	ps, err := pubsub.NewFloodSub(ctx, h)
	if err != nil {
		return nil, err
	}
	resolver := &Resolver{
		host:    h,
		dht:     kdht,
		pubsub:  ps,
		states:  map[string]types.SignedIdentityState{},
		objects: map[string][]byte{},
		topics:  map[string]*pubsub.Topic{},
	}
	h.SetStreamHandler(identityProtocol, resolver.handleStateStream)
	h.SetStreamHandler(objectProtocol, resolver.handleObjectStream)
	return resolver, nil
}

func (r *Resolver) Host() host.Host {
	return r.host
}

func (r *Resolver) Close() error {
	r.mu.Lock()
	for name, topic := range r.topics {
		if topic != nil {
			_ = topic.Close()
		}
		delete(r.topics, name)
	}
	r.mu.Unlock()
	return r.host.Close()
}

func (r *Resolver) AddrStrings() []string {
	addrs := r.host.Addrs()
	values := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		values = append(values, addr.Encapsulate(ma.StringCast("/p2p/"+r.host.ID().String())).String())
	}
	return values
}

func (r *Resolver) PublishState(ctx context.Context, state types.SignedIdentityState) error {
	r.mu.Lock()
	r.states[state.Document.ID] = state
	r.mu.Unlock()
	topic, err := r.topic(state.Document.ID)
	if err != nil {
		return err
	}
	payload, err := marshalState(state)
	if err != nil {
		return err
	}
	return topic.Publish(ctx, payload)
}

func (r *Resolver) ResolveLocal(identityID string) (types.SignedIdentityState, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	state, ok := r.states[identityID]
	return state, ok
}

func (r *Resolver) StoreObject(cid string, payload []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.objects[cid] = append([]byte(nil), payload...)
}

func (r *Resolver) ResolveObjectLocal(cid string) ([]byte, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	payload, ok := r.objects[cid]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), payload...), true
}

func (r *Resolver) SubscribeIdentity(identityID string) (*pubsub.Subscription, error) {
	topic, err := r.topic(identityID)
	if err != nil {
		return nil, err
	}
	return topic.Subscribe()
}

func (r *Resolver) ConsumeSubscription(ctx context.Context, sub *pubsub.Subscription) error {
	msg, err := sub.Next(ctx)
	if err != nil {
		return err
	}
	state, err := unmarshalState(msg.Data)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.states[state.Document.ID] = state
	r.mu.Unlock()
	return nil
}

func (r *Resolver) DialPeer(ctx context.Context, addr string) error {
	maddr, err := ma.NewMultiaddr(addr)
	if err != nil {
		return err
	}
	info, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return err
	}
	return r.host.Connect(ctx, *info)
}

func (r *Resolver) ResolveRemote(ctx context.Context, peerID peer.ID, identityID string) (types.SignedIdentityState, error) {
	stream, err := r.host.NewStream(ctx, peerID, identityProtocol)
	if err != nil {
		return types.SignedIdentityState{}, err
	}
	defer stream.Close()
	if _, err := stream.Write([]byte(identityID)); err != nil {
		return types.SignedIdentityState{}, err
	}
	if err := stream.CloseWrite(); err != nil {
		return types.SignedIdentityState{}, err
	}
	data, err := io.ReadAll(stream)
	if err != nil {
		return types.SignedIdentityState{}, err
	}
	if len(data) == 0 {
		return types.SignedIdentityState{}, errors.New("identity not found")
	}
	state, err := unmarshalState(data)
	if err != nil {
		return types.SignedIdentityState{}, err
	}
	r.mu.Lock()
	r.states[state.Document.ID] = state
	r.mu.Unlock()
	return state, nil
}

func (r *Resolver) ResolveObjectRemote(ctx context.Context, peerID peer.ID, cid string) ([]byte, error) {
	stream, err := r.host.NewStream(ctx, peerID, objectProtocol)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	if _, err := stream.Write([]byte(cid)); err != nil {
		return nil, err
	}
	if err := stream.CloseWrite(); err != nil {
		return nil, err
	}
	payload, err := io.ReadAll(stream)
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 {
		return nil, errors.New("object not found")
	}
	r.StoreObject(cid, payload)
	return payload, nil
}

func (r *Resolver) handleStateStream(stream network.Stream) {
	defer stream.Close()
	query, err := io.ReadAll(stream)
	if err != nil {
		return
	}
	identityID := string(query)
	r.mu.RLock()
	state, ok := r.states[identityID]
	r.mu.RUnlock()
	if !ok {
		return
	}
	payload, err := marshalState(state)
	if err != nil {
		return
	}
	_, _ = stream.Write(payload)
}

func (r *Resolver) handleObjectStream(stream network.Stream) {
	defer stream.Close()
	query, err := io.ReadAll(stream)
	if err != nil {
		return
	}
	cid := string(query)
	r.mu.RLock()
	payload, ok := r.objects[cid]
	r.mu.RUnlock()
	if !ok {
		return
	}
	_, _ = stream.Write(payload)
}

func (r *Resolver) topic(identityID string) (*pubsub.Topic, error) {
	name := topicName(identityID)
	r.mu.Lock()
	defer r.mu.Unlock()
	if topic, ok := r.topics[name]; ok {
		return topic, nil
	}
	topic, err := r.pubsub.Join(name)
	if err != nil {
		return nil, err
	}
	r.topics[name] = topic
	return topic, nil
}

func topicName(identityID string) string {
	return "decentid.identity." + identityID
}
