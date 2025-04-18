package firewall

import "github.com/google/nftables"

type Option func(*config)

type config struct {
	TableName        string
	TableFamily      nftables.TableFamily
	InputChainName   string
	OutputChainName  string
	ForwardChainName string
	TunIfaceName     string
}

func WithTableName(name string) Option {
	return func(c *config) {
		c.TableName = name
	}
}

func WithTableFamily(family nftables.TableFamily) Option {
	return func(c *config) {
		c.TableFamily = family
	}
}

func WithInputChainName(name string) Option {
	return func(c *config) {
		c.InputChainName = name
	}
}

func WithOutputChainName(name string) Option {
	return func(c *config) {
		c.OutputChainName = name
	}
}

func WithForwardChainName(name string) Option {
	return func(c *config) {
		c.ForwardChainName = name
	}
}

func WithTunIfaceName(name string) Option {
	return func(c *config) {
		c.TunIfaceName = name
	}
}
