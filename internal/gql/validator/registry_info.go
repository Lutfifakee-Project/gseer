// GSEER — internet-asset search engine.
// Copyright (C) 2026  The GSEER Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package validator

// registry_info.go — R79: the exported read-only view of the field
// registry.  CLI discovery surfaces (gseer fields / --examples) render
// THIS, so help can never drift from what the planner actually supports.
// Operators are derived from the same OpSet the validator enforces —
// a suggestion here is always a suggestion the validator accepts.

import (
	"sort"

	"github.com/Lutfifakee-Project/gseer/internal/gql/ast"
)

// FieldInfo is one registry entry rendered for humans.
type FieldInfo struct {
	Canonical string
	Aliases   []string
	Type      string
	Ops       []string
}

// typeNames renders the value grammar (validator.go type constants).
var typeNames = map[FieldType]string{
	TypeString: "string",
	TypeInt:    "int",
	TypeTime:   "time",
	TypeBool:   "bool",
}

// opNames renders the accepted operator set in the user-facing spelling.
var opNames = []struct {
	bit ast.OpSet
	op  string
}{
	{ast.OpSetEq, "=="},
	{ast.OpSetNeq, "!="},
	{ast.OpSetContains, "*="},
	{ast.OpSetMatch, "^="},
	{ast.OpSetLt, "<"},
	{ast.OpSetLe, "<="},
	{ast.OpSetGt, ">"},
	{ast.OpSetGe, ">="},
	{ast.OpSetIn, "in"},
	{ast.OpSetInCidr, "cidr"},
	{ast.OpSetInDomain, "domain"},
}

// FieldSummaries returns every registry entry sorted by canonical name.
func FieldSummaries() []FieldInfo {
	out := make([]FieldInfo, 0, len(fields))
	for canonical, f := range fields {
		ops := []string{}
		for _, on := range opNames {
			if f.Ops&on.bit != 0 {
				ops = append(ops, on.op)
			}
		}
		tn := typeNames[f.Type]
		if tn == "" {
			tn = "string"
		}
		out = append(out, FieldInfo{
			Canonical: canonical,
			Aliases:   append([]string(nil), f.Aliases...),
			Type:      tn,
			Ops:       ops,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Canonical < out[j].Canonical })
	return out
}
