package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/google/nftables/expr"
	"github.com/routesentry/routesentry/pkg/firewall"
	"github.com/routesentry/routesentry/pkg/routing"
)

const (
	gwIPEnvKey   = "GATEWAY_IP"
	gwPortEnvKey = "GATEWAY_PORT"
)

var (
	ethIface = GetEnvOrDefault("OIFName", "eth0")
)

func GetEnvOrExit(name string) string {
	val, ok := os.LookupEnv(name)
	if !ok {
		log.Fatalf("Missing required environment variable: %s", name)
	}
	if val == "" {
		log.Fatalf(" Environment variable %s is empty", name)
	}
	return val
}

func GetEnvOrDefault(name string, defaultVal string) string {
	if val := os.Getenv(name); val != "" {
		return val
	}
	return defaultVal
}

func LookupUDPAddrOrExit(ip string, port string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, port))
	if err != nil {
		log.Fatalf("Failed to resolve UDP address: %s", err)
	}
	return addr
}

func main() {
	gwIP := GetEnvOrExit(gwIPEnvKey)
	gwPort := GetEnvOrExit(gwPortEnvKey)

	gwAddr := LookupUDPAddrOrExit(gwIP, gwPort)

	log.Printf("Adding HostRoute to %s via %s...", gwAddr.IP, ethIface)
	err := routing.AddHostRoute(ethIface, gwAddr.IP)
	if err != nil {
		log.Fatalf("Failed to add host route: %s", err)
	}
	log.Printf("Successfully added HostRoute to %s via %s", gwAddr.IP, ethIface)

	f, err := firewall.New()
	if err != nil {
		log.Fatalf("Failed to create firewall: %s", err)
	}

	log.Printf("Configuring blackhole firewall...")
	err = ConfigureFirewallBlackHole(f)
	if err != nil {
		log.Fatalf("Failed to enable kill switch: %s", err)
	}
	log.Printf("Firewall is enabled.")
}

const (
	LoopbackIfaceName = "lo"
)

// ConfigureFirewallBlackHole sets up nftables to block all traffic except for loopback
// out on loopback device
// out on handshake traffic
// in  on existing connections
func ConfigureFirewallBlackHole(f *firewall.Firewall) error {

	loopBackRule := f.NewRuleBuilder(firewall.Output).
		MatchMetaOIFName(LoopbackIfaceName).
		Verdict(expr.VerdictAccept).
		Build()
	f.AddRule(loopBackRule)
	//
	//tunRule := f.NewRuleBuilder(firewall.Output).
	//	MatchMetaOIFName(gatewayIfaceName).
	//	Verdict(expr.VerdictAccept).
	//	Build()
	//f.AddRule(tunRule)
	//
	//handshakeRule := f.NewRuleBuilder(firewall.Output).
	//	MatchMetaOIFName(egressIfaceName).
	//	MatchL4Proto(firewall.UDP).
	//	MatchDestinationIP(gatewayAddr.IP).
	//	MatchUDPDestPort(uint16(gatewayAddr.Port)).
	//	Verdict(expr.VerdictAccept).
	//	Build()
	//f.AddRule(handshakeRule)

	//maskedStates := expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED
	//establishedRule := f.NewRuleBuilder(firewall.Input).
	//	CtStateIn(uint8(maskedStates)).
	//	Verdict(expr.VerdictAccept).
	//	Build()
	//f.AddRule(establishedRule)

	if err := f.Flush(); err != nil {
		return fmt.Errorf("error while applying firewall rules: %w", err)
	}

	return nil
}
