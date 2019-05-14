package localini

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

// Localini holds information of local network interface
type Localini struct {
	IP      net.IP
	MAC     net.HardwareAddr
	DevName string
	Name    string
}

// New creates a Localini object.
// ifi may be interface name ("Ethernet", "eth0", etc...) or ip address ("192.168.1.1", etc...)
func New(ifi string) (*Localini, error) {
	l := &Localini{}
	if err := l.set(ifi); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Localini) set(s string) error {
	ip := net.ParseIP(s)
	switch ip {
	case nil:
		ifi, err := net.InterfaceByName(s)
		if err != nil {
			return fmt.Errorf("could not find interface named: %s", s)
		}
		l.MAC, l.Name = ifi.HardwareAddr, ifi.Name
		addrs, err := ifi.Addrs()
		if err != nil {
			return err
		}
		if addrs == nil {
			return fmt.Errorf("no address found for interface: %s details: %+v", s, l)
		}
		for _, ipa := range addrs {
			ip, _, err := net.ParseCIDR(ipa.String())
			if ip.To4() == nil || err != nil {
				continue
			}
			l.IP = ip
			break
		}
	default:
		l.IP = ip
		if err := l.findMAC(); err != nil {
			return err
		}
	}

	if err := l.findDevName(); err != nil {
		return err
	}

	return nil
}

func (l *Localini) findDevName() error {
	ifis, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}
	for _, ifi := range ifis {
		for _, a := range ifi.Addresses {
			if l.IP.Equal(a.IP) {
				l.DevName = ifi.Name
				return nil
			}
		}
	}
	return fmt.Errorf("no interface matched input ip: %+v", l)
}

func (l *Localini) findMAC() error {
	ifis, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, ifi := range ifis {
		addrs, err := ifi.Addrs()
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if l.IP.Equal(ip) {
				l.MAC, l.Name = ifi.HardwareAddr, ifi.Name
				return nil
			}
		}
	}
	return fmt.Errorf("could not find local interface: %+v", l)
}
