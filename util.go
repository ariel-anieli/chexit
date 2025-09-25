package main

import (
	"C"
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type State struct{ Flag, Found, Keys, Search string }
type StateAddrGroup struct {
	Found     map[string]string
	Flag, Key string
}

//export add_addr_grp_to_search_or_get_subnet
func add_addr_grp_to_search_or_get_subnet(filename, key *C.char) *C.char {
	var state StateAddrGroup = StateAddrGroup{Key: C.GoString(key)}
	pattern := fmt.Sprintf(`edit "%s"`, state.Key)
	addrRe := regexp.MustCompile(`set (subnet|member) (.*)$`)

	file, err := os.Open(C.GoString(filename))
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		entry := scanner.Text()
		addr := addrRe.FindStringSubmatch(entry)

		if state.Key == "all" {
			state.Found = map[string]string{"subnet": "all"}
			break
		}

		if s, _ := regexp.MatchString(pattern, entry); s {
			state.Flag = "In address group"
		} else if state.Flag == "In address group" && addr != nil {
			state.Found = map[string]string{addr[1]: addr[2]}
			break
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	jsonStr, _ := json.Marshal(state.Found)
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
