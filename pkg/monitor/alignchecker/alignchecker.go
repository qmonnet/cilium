// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package alignchecker

import (
	"reflect"

	check "github.com/cilium/cilium/pkg/alignchecker"
	"github.com/cilium/cilium/pkg/monitor"
)

// CheckStructAlignments checks whether size and offsets of the C and Go
// structs for the monitor match.
//
// C struct size info is extracted from the given ELF object file debug section
// encoded in DWARF.
//
// To find a matching C struct field, a Go field has to be tagged with
// `align:"field_name_in_c_struct". In the case of unnamed union field, such
// union fields can be referred with special tags - `align:"$union0"`,
// `align:"$union1"`, etc.
func CheckStructAlignments(path string) error {
	// Validate alignments of C and Go equivalent structs
	toCheck := map[string][]reflect.Type{
		"trace_notify":      {reflect.TypeOf(monitor.TraceNotify{})},
		"drop_notify":       {reflect.TypeOf(monitor.DropNotify{})},
		"debug_msg":         {reflect.TypeOf(monitor.DebugMsg{})},
		"debug_capture_msg": {reflect.TypeOf(monitor.DebugCapture{})},
	}
	return check.CheckStructAlignments(path, toCheck)
}
