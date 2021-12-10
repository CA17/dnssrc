package netutils

import (
	"fmt"
	"strings"

	iplib "github.com/c-robinson/iplib"
)

type Net iplib.Net

func ParseIpNet(d string) (inet Net, err error) {
	if !strings.Contains(d, "/") {
		d = d + "/32"
	}
	_net := iplib.Net4FromStr(d)
	if _net.IP() == nil {
		_net6 := iplib.Net6FromStr(d)
		if _net6.IP() == nil {
			return nil, fmt.Errorf("error ip  %s", d)
		}
		return _net6, nil
	}
	return _net, nil
}

func ContainsNetAddr(ns []Net, ipstr string) bool {
	inet, err := ParseIpNet(ipstr)
	if err != nil {
		return false
	}
	for _, n := range ns {
		if n.ContainsNet(inet) {
			return true
		}
	}
	return false
}

func ContainsNet(ns []Net, net Net) bool {
	for _, n := range ns {
		if n.ContainsNet(net) {
			return true
		}
	}
	return false
}


func CompareNets(a, b Net) int {
	return iplib.CompareNets(a, b)
}

