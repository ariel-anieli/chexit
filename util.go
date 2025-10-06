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

type State struct {
	Flag   int    `json:"flag"`
	Found  string `json:"found"`
	Keys   string `json:"keys"`
	Search string `json:"search"`
}

const (
	IN_SEARCH int = iota
	WAIT_VDOM
	IN_VDOM
	IN_POLICIES
)

type addrGroup struct {
	subnets  map[string]string
	addrs    []string
	filename string
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

//export expand_subnet_from_addr_grp
func expand_subnet_from_addr_grp(CPolicy, expander, CFilename *C.char) *C.char {
	policy := &Policy{}
	json.Unmarshal([]byte(C.GoString(CPolicy)), policy)

	if C.GoString(expander) == "addr" {
		group := &addrGroup{filename: C.GoString(CFilename), addrs: policy.SrcAddr}
		policy.SrcAddr = expand_subnets(group)
		group.addrs = policy.DstAddr
		policy.DstAddr = expand_subnets(group)
	}

	jsonStr, _ := json.Marshal(policy)
	return C.CString(string(jsonStr))
}

//export search_by_uuid
func search_by_uuid(CState, CLine *C.char) *C.char {
	var state State
	var entry = strings.ReplaceAll(C.GoString(CLine), "\n", "|")

	json.Unmarshal([]byte(C.GoString(CState)), &state)

	s, _ := regexp.MatchString(`^\s*edit\s\d+`, entry)
	f, _ := regexp.MatchString(`^\s*next`, entry)

	if s {
		state.Search = entry
	} else if f && strings.Contains(state.Search, state.Keys) {
		state.Found = fmt.Sprintf("%s%s", state.Search, entry)
	} else {
		state.Search = fmt.Sprintf("%s%s", state.Search, entry)
	}

	stateAsGoString, _ := json.Marshal(state)
	return C.CString(string(stateAsGoString))
}

//export search_by_v_polid
func search_by_v_polid(CState, CLine *C.char) *C.char {
	state := &State{}
	var entry = strings.ReplaceAll(C.GoString(CLine), "\n", "|")

	json.Unmarshal([]byte(C.GoString(CState)), state)

	fields := strings.Split(state.Keys, ",")
	vdom, polID := fields[0], fields[1]
	pattern := fmt.Sprintf(`^\s*edit\s%s[^\d]`, polID)
	foundPolicy := strings.Contains(state.Search, polID)

	updateFlag(state, vdom, entry)

	if ok, _ := regexp.MatchString(pattern, entry); ok && state.Flag == IN_POLICIES {
		state.Search = entry
	} else if ok, _ := regexp.MatchString(`^\s*next`, entry); ok && foundPolicy {
		state.Found = fmt.Sprintf("%s%s", state.Search, entry)
	} else if state.Search != "" && state.Flag == IN_POLICIES {
		state.Search = fmt.Sprintf("%s%s", state.Search, entry)
	}

	stateAsGoString, _ := json.Marshal(state)
	return C.CString(string(stateAsGoString))
}

//export trim_keys
func trim_keys(found *C.char) *C.char {
	var fields map[string]interface{} = make(map[string]interface{})

	for _, field := range strings.Split(C.GoString(found), "|") {
		key, val := split_field(field)
		fields[key] = val
	}

	jsonStr, _ := json.Marshal(fields)

	return C.CString(string(jsonStr))
}

//export trim_prfx
func trim_prfx(found *C.char) *C.char {
	var output string = C.GoString(found)
	var keyset map[string]string = map[string]string{
		`^\s+edit\s`:   "id ",
		`\|\s+set\s`:   "|",
		`\|\s+next.*$`: "",
		`"`:            "",
	}

	for pattern, replacement := range keyset {
		re := regexp.MustCompile(pattern)
		output = re.ReplaceAllString(output, replacement)
	}

	return C.CString(output)
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

func expand_subnets(group *addrGroup) []string {
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

func updateFlag(state *State, vdom, entry string) {
	switch state.Flag {
	case IN_SEARCH:
		if ok, _ := regexp.MatchString(`^\s*config global`, entry); ok {
			state.Flag = WAIT_VDOM
		}
	case WAIT_VDOM:
		pattern := fmt.Sprintf(`^\s*edit\s%s`, vdom)
		if ok, _ := regexp.MatchString(pattern, entry); ok {
			state.Flag = IN_VDOM
		}
	case IN_VDOM:
		if ok, _ := regexp.MatchString(`\s*config firewall policy`, entry); ok {
			state.Flag = IN_POLICIES
		}
	case IN_POLICIES:
		state.Flag = IN_POLICIES
	}
}

func main() {
}
