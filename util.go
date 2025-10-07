package main

import (
	"C"
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
	IN_SEARCH int = iota
	WAIT_VDOM
	IN_VDOM
	IN_POLICIES
)

type LookUp struct {
	Expander string `json:"expander"`
	Filename string `json:"filename"`
	Key      string `json:"key"`
	SearchBy string `json:"search-by"`
}

type Policy struct {
	ID       int      `json:"id"`
	Name     string   `json:"name"`
	UUID     string   `json:"uuid"`
	Srcintf  []string `json:"srcintf"`
	DstIntf  []string `json:"dstintf"`
	SrcAddr  []string `json:"srcaddr"`
	DstAddr  []string `json:"dstaddr"`
	Service  []string `json:"service"`
	Schedule []string `json:"schedule"`
	Action   string   `json:"action"`
}

type addrGroup struct {
	subnets  map[string]string
	addrs    []string
	filename string
}

type state struct {
	flag   int    `json:"flag"`
	found  string `json:"found"`
	keys   string `json:"keys"`
	search string `json:"search"`
}

//export lookup_key
func lookup_key(CLookUp *C.char) *C.char {
	policy := &Policy{}
	lookup := &LookUp{}
	json.Unmarshal([]byte(C.GoString(CLookUp)), lookup)
	var searchBy func(*state, string)
	state := &state{keys: lookup.Key}

	switch lookup.SearchBy {
	case "UUID":
		searchBy = searchByUUID
	case "VDOM-AND-POLID":
		searchBy = searchByVDOMAndPolID
	}

	file, err := os.Open(lookup.Filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		searchBy(state, line)
		if state.found != "" {
			trimPrefix(&state.found)
			jsonBody, _ := json.Marshal(trimKeys(state.found))
			json.Unmarshal(jsonBody, policy)
			expandSubnetFromAddrGroup(policy, lookup)
			goto exit
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

exit:
	jsonStr, _ := json.Marshal(policy)
	return C.CString(string(jsonStr))
}

func add_addr_or_subnet(group *addrGroup) {
	const (
		IN_GRP int = iota
		IN_ADDR
	)

	var key string
	var flag int

	key, group.addrs = group.addrs[0], group.addrs[1:]
	pattern := fmt.Sprintf(`edit "%s"`, key)
	addrRe := regexp.MustCompile(`set (subnet|member) (.*)$`)

	file, err := os.Open(group.filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	if key == "all" {
		group.subnets["all"] = "all"
		return
	}

	for scanner.Scan() {
		entry := scanner.Text()
		addr := addrRe.FindStringSubmatch(entry)

		if ok, _ := regexp.MatchString(`config firewall addrgrp`, entry); ok {
			flag = IN_GRP
		} else if ok, _ := regexp.MatchString(pattern, entry); ok && flag == IN_GRP {
			flag = IN_ADDR
		} else if flag == IN_ADDR && addr != nil {
			if addr[1] == "subnet" {
				addSubnet(addr[2], group)
			} else if addr[1] == "member" {
				addAddrs(addr[2], group)
			}
			return
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func addAddrs(addr string, group *addrGroup) {
	for _, member := range strings.Split(addr, " ") {
		group.addrs = append(group.addrs, strings.ReplaceAll(member, `"`, ""))
	}
}

func addSubnet(addr string, group *addrGroup) {
	fields := strings.Split(addr, " ")
	subnet := fmt.Sprintf("%s/%s", fields[0], getCIDR(fields[1]))
	group.subnets[subnet] = subnet
}

func expandSubnetFromAddrGroup(policy *Policy, lookUp *LookUp) {
	if lookUp.Expander == "addr" {
		group := &addrGroup{filename: lookUp.Filename, addrs: policy.SrcAddr}
		policy.SrcAddr = expandSubnets(group)
		group.addrs = policy.DstAddr
		policy.DstAddr = expandSubnets(group)
	}
}

func expandSubnets(group *addrGroup) []string {
	group.subnets = make(map[string]string)
	for len(group.addrs) != 0 {
		for _ = range len(group.addrs) {
			add_addr_or_subnet(group)
		}
	}

	return slices.Collect(maps.Keys((*group).subnets))
}

func getCIDR(mask string) string {
	length, _ := net.IPMask(net.ParseIP(mask).To4()).Size()
	return strconv.Itoa(length)
}

func searchByVDOMAndPolID(state *state, line string) {
	var entry string = line + "|"

	fields := strings.Split(state.keys, ",")
	vdom, polID := fields[0], fields[1]
	pattern := fmt.Sprintf(`^\s*edit\s%s[^\d]`, polID)
	foundPolicy := strings.Contains(state.search, polID)

	updateFlag(state, vdom, entry)

	if ok, _ := regexp.MatchString(pattern, entry); ok && state.flag == IN_POLICIES {
		state.search = entry
	} else if ok, _ := regexp.MatchString(`^\s*next`, entry); ok && foundPolicy {
		state.found = fmt.Sprintf("%s%s", state.search, entry)
	} else if state.search != "" && state.flag == IN_POLICIES {
		state.search = fmt.Sprintf("%s%s", state.search, entry)
	}
}

func searchByUUID(state *state, line string) {
	var entry string = line + "|"

	s, _ := regexp.MatchString(`^\s*edit\s\d+`, entry)
	f, _ := regexp.MatchString(`^\s*next`, entry)

	if s {
		state.search = entry
	} else if f && strings.Contains(state.search, state.keys) {
		state.found = fmt.Sprintf("%s%s", state.search, entry)
	} else {
		state.search = fmt.Sprintf("%s%s", state.search, entry)
	}
}

func split_field(field string) (string, interface{}) {
	var fields []string = strings.Split(field, " ")

	m, _ := regexp.MatchString(`^(id|name|action|logtraffic|uuid|comments)`, field)
	if !m {
		return fields[0], fields[1:]
	} else if fields[0] != "id" {
		return fields[0], fields[1]
	} else {
		val, _ := strconv.Atoi(fields[1])
		return fields[0], val
	}
}

func trimKeys(found string) map[string]interface{} {
	fields := make(map[string]interface{})

	for _, field := range strings.Split(found, "|") {
		key, val := split_field(field)
		fields[key] = val
	}

	return fields
}

func trimPrefix(found *string) {
	var keyset map[string]string = map[string]string{
		`^\s+edit\s`:   "id ",
		`\|\s+set\s`:   "|",
		`\|\s+next.*$`: "",
		`"`:            "",
	}

	for pattern, replacement := range keyset {
		re := regexp.MustCompile(pattern)
		*found = re.ReplaceAllString(*found, replacement)
	}
}

func updateFlag(state *state, vdom, entry string) {
	switch state.flag {
	case IN_SEARCH:
		if ok, _ := regexp.MatchString(`^\s*config global`, entry); ok {
			state.flag = WAIT_VDOM
		}
	case WAIT_VDOM:
		pattern := fmt.Sprintf(`^\s*edit\s%s`, vdom)
		if ok, _ := regexp.MatchString(pattern, entry); ok {
			state.flag = IN_VDOM
		}
	case IN_VDOM:
		if ok, _ := regexp.MatchString(`\s*config firewall policy`, entry); ok {
			state.flag = IN_POLICIES
		}
	case IN_POLICIES:
		state.flag = IN_POLICIES
	}
}

func main() {
}
