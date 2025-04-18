package firewall

import (
	"fmt"

	"github.com/google/nftables"
	"k8s.io/utils/ptr"
)

const (
	nftableName      = "routesentry"
	inputChainName   = nftableName + "_input"
	outputChainName  = nftableName + "_output"
	forwardChainName = nftableName + "_forward"
	tunIface         = "wg0"
)

type ChainType int

const (
	Input = iota
	Output
	Forward
)

type Firewall struct {
	conn         *nftables.Conn
	table        *nftables.Table
	inChain      *nftables.Chain
	outChain     *nftables.Chain
	forwardChain *nftables.Chain
	tunIfaceName string
}

func New(opts ...Option) (*Firewall, error) {

	cfg := &config{
		TableName:        nftableName,
		TableFamily:      nftables.TableFamilyINet,
		InputChainName:   inputChainName,
		OutputChainName:  outputChainName,
		ForwardChainName: forwardChainName,
		TunIfaceName:     tunIface,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create nftables connection: %w", err)
	}
	// remove all existing rules
	conn.FlushRuleset()

	// create our rules
	table := &nftables.Table{
		Name:   cfg.TableName,
		Family: cfg.TableFamily,
	}
	conn.AddTable(table)

	inChain := conn.AddChain(&nftables.Chain{
		Name:     cfg.InputChainName,
		Table:    table,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
		Policy:   ptr.To(nftables.ChainPolicyDrop),
	})

	outChain := conn.AddChain(&nftables.Chain{
		Name:     cfg.OutputChainName,
		Table:    table,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
		Policy:   ptr.To(nftables.ChainPolicyDrop),
	})

	forwardChain := conn.AddChain(&nftables.Chain{
		Name:     cfg.ForwardChainName,
		Table:    table,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Type:     nftables.ChainTypeFilter,
		Policy:   ptr.To(nftables.ChainPolicyDrop),
	})

	return &Firewall{
		conn:         conn,
		table:        table,
		inChain:      inChain,
		outChain:     outChain,
		forwardChain: forwardChain,
		tunIfaceName: cfg.TunIfaceName,
	}, nil
}

func (f *Firewall) AddRule(r *nftables.Rule) *nftables.Rule {
	return f.conn.AddRule(r)
}

func (f *Firewall) Flush() error {
	return f.conn.Flush()
}

func (f *Firewall) NewRuleBuilder(c ChainType) *RuleBuilder {
	switch c {
	case Input:
		return newRuleBuilder(f.table, f.inChain)
	case Output:
		return newRuleBuilder(f.table, f.outChain)
	case Forward:
		return newRuleBuilder(f.table, f.forwardChain)
	default:
		return nil
	}
}
