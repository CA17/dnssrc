package dnssrc

import (
	"bufio"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ca17/dnssrc/plugin/pkg/netutils"
)

const (
	NetaddrItemTypePath = iota
	NetaddrItemTypeUrl
	NetaddrItemTypeDefault    // Dummy
)

type NetaddrList struct {
	// List of name items
	items []*NetaddrItem

	// All name items shared the same reload duration

	pathReload     time.Duration
	stopPathReload chan struct{}

	urlReload      time.Duration
	urlReadTimeout time.Duration
	stopUrlReload  chan struct{}
}


// Assume `child' is lower cased and without trailing dot
func (n *NetaddrList) Match(child string) bool {
	for _, item := range n.items {
		item.RLock()
		if item.Match(child) {
			item.RUnlock()
			return true
		}
		item.RUnlock()
	}
	return false
}

// MT-Unsafe
func (n *NetaddrList) periodicUpdate(bootstrap []string) {
	// Kick off initial name list content population
	if n.pathReload > 0 {
		go func() {
			ticker := time.NewTicker(n.pathReload)
			for {
				select {
				case <-n.stopPathReload:
					return
				case <-ticker.C:
					n.updateList(NetaddrItemTypePath, bootstrap)
				}
			}
		}()
	}

	if n.urlReload > 0 {
		go func() {
			ticker := time.NewTicker(n.urlReload)
			for {
				select {
				case <-n.stopUrlReload:
					return
				case <-ticker.C:
					n.updateList(NetaddrItemTypeUrl, bootstrap)
				}
			}
		}()
	}
}

func (n *NetaddrList) updateList(whichType int, bootstrap []string) {
	for _, item := range n.items {
		if whichType == item.whichType {
			switch item.whichType {
			case NetaddrItemTypePath:
				n.updateItemFromPath(item)
			case NetaddrItemTypeUrl:
				_ = n.updateItemFromUrl(item, bootstrap)
			default:
				log.Errorf("Unexpected NameItem type %v", whichType)
			}
		}
	}
}

func (n *NetaddrList) updateItemFromPath(item *NetaddrItem) {
	file, err := os.Open(item.path)
	if err != nil {
		if os.IsNotExist(err) {
			// File not exist already reported at setup stage
			log.Debugf("%v", err)
		} else {
			log.Warningf("%v", err)
		}
		return
	}
	defer Close(file)

	stat, err := file.Stat()
	if err == nil {
		item.RLock()
		mtime := item.mtime
		size := item.size
		item.RUnlock()

		if stat.ModTime() == mtime && stat.Size() == size {
			return
		}
	} else {
		// Proceed parsing anyway
		log.Warningf("%v", err)
	}

	t1 := time.Now()
	addrs, totalLines := n.parse(file)
	t2 := time.Since(t1)
	log.Debugf("Parsed %v  time spent: %v name added: %v / %v",file.Name(), t2, len(addrs), totalLines)

	item.Lock()
	item.addrs = addrs
	item.mtime = stat.ModTime()
	item.size = stat.Size()
	item.Unlock()
}

func (n *NetaddrList) parse(r io.Reader) ([]netutils.Net, uint64) {
	addrs := make([]netutils.Net, 0)
	var totalLines uint64
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		totalLines++

		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}

		addr ,err := netutils.ParseIpNet(line)
		if err != nil {
			log.Errorf("error dnssrc netaddr %s %s", line, err.Error())
			continue
		}

		for _, inet := range addrs {
			if addr.ContainsNet(inet) {
				log.Warningf("%s ContainsNet %s", addr.String(), inet.String())
				continue
			}
		}
		addrs = append(addrs, addr)
	}

	return addrs, totalLines
}

// Return true if NameItem updated
func (n *NetaddrList) updateItemFromUrl(item *NetaddrItem, bootstrap []string) bool {
	if item.whichType != NetaddrItemTypeUrl || len(item.url) == 0 {
		log.Warningf("Function call misuse or bad URL %s config", item.url)
		return false
	}

	t1 := time.Now()
	content, err := getUrlContent(item.url, "text/plain", bootstrap, n.urlReadTimeout)
	t2 := time.Since(t1)
	if err != nil {
		log.Warningf("Failed to update %q, err: %v", item.url, err)
		return false
	}

	item.RLock()
	contentHash := item.contentHash
	item.RUnlock()
	contentHash1 := stringHash(content)
	if contentHash1 == contentHash {
		return true
	}

	addrs := make([]netutils.Net, 0)
	var totalLines uint64
	t3 := time.Now()
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		totalLines++

		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}

		addr ,err := netutils.ParseIpNet(line)
		if err != nil {
			log.Errorf("error dnssrc netaddr %s %s", line, err.Error())
			continue
		}

		for _, inet := range addrs {
			if addr.ContainsNet(inet) {
				log.Warningf("%s ContainsNet %s", addr.String(), inet.String())
				continue
			}
		}
		addrs = append(addrs, addr)
	}
	t4 := time.Since(t3)
	log.Debugf("Fetched %v, time spent: %v %v, added: %v / %v, hash: %#x",
		item.url, t2, t4, len(addrs), totalLines, contentHash1)

	item.Lock()
	item.addrs = addrs
	item.contentHash = contentHash1
	item.Unlock()

	return true
}

