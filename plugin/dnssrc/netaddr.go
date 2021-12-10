package dnssrc

import (
	"strings"
	"sync"
	"time"

	"github.com/ca17/dnssrc/plugin/pkg/common"
	"github.com/ca17/dnssrc/plugin/pkg/netutils"
)

type NetaddrItem struct {
	sync.RWMutex

	// net addr set for lookups
	addrs []netutils.Net

	whichType int

	path  string
	mtime time.Time
	size  int64

	url         string
	contentHash uint64
}

func NewNetaddrItemsWithForms(forms []string) ([]*NetaddrItem, error) {
	items := make([]*NetaddrItem, 0)
	defaultItem := &NetaddrItem{whichType: NetaddrItemTypeDefault}
	items = append(items, defaultItem)
	for _, from := range forms {
		switch {
		case strings.HasPrefix(strings.ToLower(from), "http://"):
			log.Warningf("Due to security reasons, URL %q is prohibited", from)
		case strings.HasPrefix(strings.ToLower(from), "https://"):
			items = append(items, &NetaddrItem{
				whichType: NetaddrItemTypeUrl,
				url:       from,
			})
		case common.IsFilePath(from):
			items = append(items, &NetaddrItem{
				whichType: NetaddrItemTypePath,
				path:      from,
			})
		default:
			defaultItem.Add(from)
		}
	}
	return items, nil
}

func (d *NetaddrItem) Len() int {
	return len(d.addrs)
}

func (d *NetaddrItem) Add(ipstr string) bool {
	if d.Match(ipstr) {
		return false
	}
	n, err := netutils.ParseIpNet(ipstr)
	if err != nil {
		return false
	}
	d.addrs = append(d.addrs, n)
	return true
}

func (d *NetaddrItem) Match(ipstr string) bool {
	n, err := netutils.ParseIpNet(ipstr)
	if err != nil {
		return false
	}
	for _, inet := range d.addrs {
		if inet.ContainsNet(n) {
			return true
		}
	}
	return false
}
