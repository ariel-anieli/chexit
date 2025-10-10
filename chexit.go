package main

import (
	"C"
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"maps"
	"net"
	"os"
	"reflect"
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

const (
	UUID int = iota
	VDOM_AND_POLID
)

type LookUp struct {
	Expander     string
	Filename     string
	Keys         string
	Formatter    string
	UUID, vPolID string
	Verbose      int
	SearchBy     int
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

func main() {
	lookup := parseArgs()

	if errors := checkArgs(lookup); len(errors) > 0 {
		log.Printf("Invalid arguments: %s\n", strings.Join(errors, ", "))
		os.Exit(1)
	}

	if lookup.UUID != "" {
		lookup.SearchBy = UUID
		lookup.Keys = lookup.UUID
	} else if lookup.vPolID != "" {
		lookup.SearchBy = VDOM_AND_POLID
		lookup.Keys = lookup.vPolID
	}

	fmt.Println(Format(LookUpKeys(&lookup), lookup.Formatter))
}

func Format(policies []Policy, formatter string) string {
	var formatted string

	switch formatter {
	case "json":
		jsonStr, _ := json.Marshal(policies)
		formatted = string(jsonStr)
	case "csv":
		for _, policy := range policies {
			formatted = fmt.Sprintf("%s%s", formatted, policytoString(policy))
		}
	}

	return formatted
}

func LookUpKeys(lookUp *LookUp) []Policy {
	var policies []Policy

	for _, key := range strings.Split(lookUp.Keys, ":") {
		policies = append(policies, lookupKey(key, lookUp))
	}

	return policies
}

func addAddrOrSubnet(group *addrGroup) {
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

func checkArgs(lookup LookUp) []string {
	var errors []string
	conditions := map[string]bool{
		"no filename":                    lookup.Filename == "",
		"both UUID & VDOM/Policy ID set": lookup.UUID != "" && lookup.vPolID != "",
		"UUID or VDOM/Policy ID not set": lookup.UUID == "" && lookup.vPolID == "",
	}

	for msg, condition := range conditions {
		if condition {
			errors = append(errors, msg)
		}
	}

	return errors
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
			addAddrOrSubnet(group)
		}
	}

	return slices.Collect(maps.Keys((*group).subnets))
}

func getCIDR(mask string) string {
	length, _ := net.IPMask(net.ParseIP(mask).To4()).Size()
	return strconv.Itoa(length)
}

func lookupKey(key string, lookUp *LookUp) Policy {
	policy := &Policy{}
	var searchBy func(*state, string)
	state := &state{keys: key}

	switch lookUp.SearchBy {
	case UUID:
		searchBy = searchByUUID
	case VDOM_AND_POLID:
		searchBy = searchByVDOMAndPolID
	}

	file, err := os.Open(lookUp.Filename)
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
			expandSubnetFromAddrGroup(policy, lookUp)
			goto exit
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

exit:
	return *policy
}

func parseArgs() LookUp {
	var lookup LookUp

	flag.StringVar(&lookup.Filename, "config", "", "Configuration file name")
	flag.IntVar(&lookup.Verbose, "verbose", 0, "Verbosity")
	flag.StringVar(&lookup.Expander, "expand", "addr", "Expand (none, addr)")
	flag.StringVar(&lookup.Formatter, "formatter", "json", "Output format (json, csv)")
	flag.StringVar(&lookup.UUID, "uuid", "", "uuid1[:uuid2...]")
	flag.StringVar(&lookup.vPolID, "v_polid", "", "vdom1,polID1[:vdom2,polID2...]")

	flag.Parse()

	return lookup
}

func policytoString(policy Policy) string {
	var key, head, rows string
	sep := ";"
	values := reflect.ValueOf(policy)
	typesOf := values.Type()

	for i := 0; i < values.NumField(); i++ {
		key = strings.ToLower(typesOf.Field(i).Name)

		switch key {
		case "id":
			head = fmt.Sprintf("%s", key)
			rows = fmt.Sprintf("%d", values.Field(i).Interface())
		case "name", "uuid", "action", "logtraffic", "comments":
			head = fmt.Sprintf("%s%s%s", head, sep, key)
			rows = fmt.Sprintf("%s%s%s", rows, sep, values.Field(i).Interface())
		case "srcintf", "dstintf", "srcaddr", "dstaddr", "schedule", "service":
			head = fmt.Sprintf("%s%s%s", head, sep, key)
			values := values.Field(i).Interface().([]string)
			rows = fmt.Sprintf("%s%s%s", rows, sep, strings.Join(values, ","))
		}
	}

	return fmt.Sprintf("sep=%s\n%s\n%s", sep, head, rows)
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
