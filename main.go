package main

import (
	"C"
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"net"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

const (
	UUID int = iota
	VDOM_AND_POLID
)

type Config struct {
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

const (
	IN_SEARCH int = iota
	WAIT_VDOM
	IN_VDOM
	IN_POLICIES
)

type state struct {
	flag   int
	found  string
	keys   string
	search string
}

func main() {
	config := parseArgs()
	_logger := startLogger(config.Verbose)

	if errors := checkArgs(config); errors != "" {
		_logger.error(fmt.Sprintf("Invalid arguments: %s\n", errors))
		stopLogger(_logger)
		os.Exit(1)
	}

	if config.UUID != "" {
		config.SearchBy = UUID
		config.Keys = config.UUID
	} else if config.vPolID != "" {
		config.SearchBy = VDOM_AND_POLID
		config.Keys = config.vPolID
	}

	_logger.info(Format(LookUpKeys(_logger, &config), config.Formatter))
	stopLogger(_logger)
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

type message struct {
	id     string
	status workerState
	policy Policy
}

type workerState int

const (
	_ workerState = iota
	WORK
	DONE
)

func LookUpKeys(_logger *logger, config *Config) []Policy {
	var (
		policies      []Policy
		policyCh      (chan message)
		searchBy      func(*logger, string, chan string, chan message)
		lines, worker sync.Map
		done          bool
	)

	searchBy = searchByUUID

	file, err := os.Open(config.Filename)
	if err != nil {
		_logger.error(err.Error())
		os.Exit(1)
	}
	defer file.Close()

	for _, key := range strings.Split(config.Keys, ":") {
		worker.Store(key, WORK)
		ch := make(chan string)
		lines.Store(key, ch)

		go searchBy(_logger, key, ch, policyCh)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		select {
		default:
			line := scanner.Text()
			for _, key := range strings.Split(config.Keys, ":") {
				if state, _ := worker.Load(key); state == WORK {
					ch, _ := lines.Load(key)
					ch.(chan string) <- line
					_logger.debug(fmt.Sprintf("%+v to wk", line))
				}
			}
		case msg := <-policyCh:
			policies = append(policies, msg.policy)

			worker.Swap(msg.id, msg.status)
			ch, _ := lines.Load(msg.id)
			close(ch.(chan string))

			done = true
			for _, key := range strings.Split(config.Keys, ":") {
				if state, _ := worker.Load(key); state == WORK {
					done = false
					break
				}
			}

			if done {
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		_logger.error(err.Error())
		os.Exit(1)
	}

	return policies
}

func addAddrOrSubnet(_logger *logger, group *addrGroup) {
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
		_logger.error(err.Error())
		os.Exit(1)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	if key == "all" {
		group.subnets["all"] = "all"
		_logger.debug(fmt.Sprintf("Found subnet all"))
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
			_logger.debug(fmt.Sprintf("%s: %s", key, addr[2]))
			return
		}
	}

	if err := scanner.Err(); err != nil {
		_logger.error(err.Error())
		os.Exit(1)
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

func checkArgs(config Config) string {
	var errors []string
	conditions := map[string]bool{
		"no filename":                    config.Filename == "",
		"both UUID & VDOM/Policy ID set": config.UUID != "" && config.vPolID != "",
		"UUID or VDOM/Policy ID not set": config.UUID == "" && config.vPolID == "",
	}

	for msg, condition := range conditions {
		if condition {
			errors = append(errors, msg)
		}
	}

	return strings.Join(errors, ", ")
}

func expandSubnets(_logger *logger, group *addrGroup) []string {
	group.subnets = make(map[string]string)
	for len(group.addrs) != 0 {
		for _ = range len(group.addrs) {
			addAddrOrSubnet(_logger, group)
		}
	}

	return slices.Collect(maps.Keys((*group).subnets))
}

func getCIDR(mask string) string {
	length, _ := net.IPMask(net.ParseIP(mask).To4()).Size()
	return strconv.Itoa(length)
}

func parseArgs() Config {
	var config Config

	flag.StringVar(&config.Filename, "config", "", "Configuration file name")
	flag.IntVar(&config.Verbose, "verbose", 0, "Verbosity")
	flag.StringVar(&config.Expander, "expand", "addr", "Expand (none, addr)")
	flag.StringVar(&config.Formatter, "formatter", "json", "Output format (json, csv)")
	flag.StringVar(&config.UUID, "uuid", "", "uuid1[:uuid2...]")
	flag.StringVar(&config.vPolID, "v_polid", "", "vdom1,polID1[:vdom2,polID2...]")

	flag.Parse()

	return config
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

func searchByVDOMAndPolID(_logger *logger, state *state, line string) {
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
		_logger.debug(fmt.Sprintf("Found ID %s in VDOM %s", polID, vdom))
	} else if state.search != "" && state.flag == IN_POLICIES {
		state.search = fmt.Sprintf("%s%s", state.search, entry)
	}
}

func searchByUUID(_logger *logger, key string, lines chan string, policyCh chan message) {
	var (
		policy Policy
		state  state = state{keys: key}
		entry  string
	)

	for line := range lines {
		entry = line + "|"

		s, _ := regexp.MatchString(`^\s*edit\s\d+`, entry)
		f, _ := regexp.MatchString(`^\s*next`, entry)

		if s {
			state.search = entry
		} else if f && strings.Contains(state.search, state.keys) {
			state.found = fmt.Sprintf("%s%s", state.search, entry)
			_logger.debug(fmt.Sprintf("Found %s", state.keys))
		} else {
			state.search = fmt.Sprintf("%s%s", state.search, entry)
		}

		if state.found != "" {
			trimPrefix(&state.found)
			jsonBody, _ := json.Marshal(trimKeys(state.found))
			json.Unmarshal(jsonBody, &policy)
			break
		}
	}

	_logger.debug(fmt.Sprintf("policy %+v in worker %+v\n", policy, key))
	policyCh <- message{id: key, status: DONE, policy: policy}
}

func splitField(field string) (string, interface{}) {
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
		key, val := splitField(field)
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
