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

type State struct{ Flag, Found, Keys, Search string }

type StateAddrGroup struct {
	Subnets  map[string]string
	Addrs    []string
	Filename string
}

//export search_till_subnet_is_found
func search_till_subnet_is_found(CState *C.char) *C.char {
	state := &StateAddrGroup{}
	json.Unmarshal([]byte(C.GoString(CState)), state)

	for len(state.Addrs) != 0 {
		for _ = range len(state.Addrs) {
			add_addr_grp_to_search_or_get_subnet(state)
		}
	}

	subnets := slices.Collect(maps.Keys((*state).Subnets))
	jsonStr, _ := json.Marshal(subnets)
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

func add_addr_grp_to_search_or_get_subnet(state *StateAddrGroup) {
	const (
		IN_GRP int = iota
		IN_ADDR
	)

	var key string
	var flag int

	key, state.Addrs = state.Addrs[0], state.Addrs[1:]
	pattern := fmt.Sprintf(`edit "%s"`, key)
	addrRe := regexp.MustCompile(`set (subnet|member) (.*)$`)

	file, err := os.Open(state.Filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	if key == "all" {
		state.Subnets["all"] = "all"
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
				addSubnet(addr[2], state)
			} else if addr[1] == "member" {
				addAddrs(addr[2], state)
			}
			return
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func addAddrs(addr string, state *StateAddrGroup) {
	for _, member := range strings.Split(addr, " ") {
		state.Addrs = append(state.Addrs, strings.ReplaceAll(member, `"`, ""))
	}
}

func addSubnet(addr string, state *StateAddrGroup) {
	fields := strings.Split(addr, " ")
	subnet := fmt.Sprintf("%s/%s", fields[0], getCIDR(fields[1]))
	state.Subnets[subnet] = subnet
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

func main() {
}
