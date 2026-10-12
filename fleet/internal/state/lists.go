package state

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/williamsouzadelima/suricatoos-infra/fleet/contract"
)

// listSpec is how one list kind is finished (finishList).
type listSpec[T any] struct {
	max    int             // the schema's maxItems
	tenant func(*T) string // the item's tenant
	// prepare normalizes the item's own lists — on a copy, never the source's slice — and reports whether it had to
	// cut one that has no count of its own (the snapshot is then marked truncated). Optional.
	prepare func(*T) bool
	valid   func(*T) bool   // every constraint of the schema on the item, its tenant aside
	key     func(*T) string // the sort key; nil keeps the source's order (reports: most recent first)
	wrap    func(items []T, truncated bool, unattributed int64) any
}

// finishList turns what a source returned into the bytes of data_<kind>, under the rules of ADR-0011 "Estado" and
// "Multi-tenant":
//
//   - an item whose tenant is not known (known) — no owner mapped to it, a name outside the tenant pattern — is
//     never listed, only counted in unattributed_count; so is an item the schema would refuse (an id that is no
//     UUID, a hostname among the literal hosts, a control character in a name...): the source got it wrong, and
//     one bad item never takes the snapshot with it;
//   - the rest is sorted by key, with the item's own bytes as the tie-break, so the same state gives the same bytes
//     whatever order the source used;
//   - the list is cut at the schema's maxItems, then at limit bytes for the whole data, and a cut sets truncated: a
//     kind that would go over 16 MiB is cut, never sent whole nor invalid.
//
// The source's own truncated and unattributed_count carry over (a negative count is refused).
func finishList[T any](spec listSpec[T], items []T, truncated bool, unattributed int64, known func(string) bool,
	limit int) ([]byte, error) {
	if unattributed < 0 {
		return nil, errors.New("state: unattributed_count negativo na fonte")
	}
	type entry struct {
		item T
		key  string
		enc  []byte
	}
	kept := make([]entry, 0, len(items))
	for i := range items {
		it := items[i]
		if !known(spec.tenant(&it)) {
			unattributed++
			continue
		}
		cut := spec.prepare != nil && spec.prepare(&it)
		if !spec.valid(&it) {
			unattributed++
			continue
		}
		enc, err := contract.MarshalCompact(it)
		if err != nil {
			unattributed++
			continue
		}
		truncated = truncated || cut
		e := entry{item: it, enc: enc}
		if spec.key != nil {
			e.key = spec.key(&it)
		}
		kept = append(kept, e)
	}
	if spec.key != nil {
		slices.SortStableFunc(kept, func(a, b entry) int {
			if c := strings.Compare(a.key, b.key); c != 0 {
				return c
			}
			return bytes.Compare(a.enc, b.enc)
		})
	}
	if len(kept) > spec.max {
		kept, truncated = kept[:spec.max], true
	}

	base := func(tr bool) (int, error) {
		b, err := contract.MarshalCompact(spec.wrap([]T{}, tr, unattributed))
		return len(b), err
	}
	size, err := base(truncated)
	if err != nil {
		return nil, err
	}
	for i, e := range kept {
		size += len(e.enc)
		if i > 0 {
			size++ // the comma
		}
	}
	if size > limit {
		truncated = true
		if size, err = base(true); err != nil {
			return nil, err
		}
		n := 0
		for i, e := range kept {
			add := len(e.enc)
			if i > 0 {
				add++
			}
			if size+add > limit {
				break
			}
			size += add
			n = i + 1
		}
		if n == len(kept) && n > 0 {
			// everything fits only because "true" is one byte shorter than "false": truncated must not lie, so
			// one item does go
			n--
		}
		kept = kept[:n]
	}

	out := make([]T, len(kept))
	for i := range kept {
		out[i] = kept[i].item
	}
	data, err := contract.MarshalCompact(spec.wrap(out, truncated, unattributed))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("state: data com %d bytes acima do teto de %d", len(data), limit) // unreachable
	}
	return data, nil
}

// all reports whether every element satisfies ok.
func all[T any](xs []T, ok func(T) bool) bool {
	for _, x := range xs {
		if !ok(x) {
			return false
		}
	}
	return true
}

// nonNegative reports whether every value is >= 0 (the schema's minimum of counts).
func nonNegative(vs ...int64) bool {
	for _, v := range vs {
		if v < 0 {
			return false
		}
	}
	return true
}

func optNonNegative(v *int64) bool { return v == nil || *v >= 0 }
