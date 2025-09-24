package main

import (
	"C"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type State struct{ Flag, Found, Keys, Search string }

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
