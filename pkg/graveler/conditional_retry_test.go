package graveler_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/graveler"
	"github.com/treeverse/lakefs/pkg/graveler/staging"
	"github.com/treeverse/lakefs/pkg/graveler/testutil"
	"github.com/treeverse/lakefs/pkg/kv"
	"github.com/treeverse/lakefs/pkg/kv/kvtest"
	"go.uber.org/ratelimit"
)

// sealingStaging wraps the real staging manager. After the first successful
// Update it runs onFirstUpdate, which simulates a commit sealing the token
// between safeBranchWrite's write and its re-check of the branch.
type sealingStaging struct {
	*staging.Manager
	onFirstUpdate func()
	done          bool
}

func (s *sealingStaging) Update(ctx context.Context, st graveler.StagingToken, key graveler.Key, f graveler.ValueUpdateFunc) error {
	err := s.Manager.Update(ctx, st, key, f)
	if err == nil && !s.done && s.onFirstUpdate != nil {
		s.done = true
		s.onFirstUpdate()
	}
	return err
}

func ifAbsent(v *graveler.Value) error {
	if v != nil {
		return graveler.ErrPreconditionFailed
	}
	return nil
}

// runIfNoneMatch writes obj with If-None-Match. With seal, a commit seals the
// staging token right after the first write. With other, another writer also
// stages a different obj in the new token before the retry.
func runIfNoneMatch(t *testing.T, seal, other bool) (error, *graveler.Value) {
	return runIfNoneMatchWith(t, seal, other, "id-2")
}

// runIfNoneMatchWith is runIfNoneMatch with the identity of the other writer's value.
func runIfNoneMatchWith(t *testing.T, seal, other bool, otherIdentity string) (error, *graveler.Value) {
	ctx := t.Context()
	store := kvtest.GetStore(ctx, t)
	sm := staging.NewManager(ctx, store, kv.NewStoreLimiter(store, ratelimit.NewUnlimited()), false, nil)
	refs := &testutil.RefsFake{
		RefType:      graveler.ReferenceTypeBranch,
		StagingToken: "t1",
		Branch:       &graveler.Branch{StagingToken: "t1"},
	}
	ss := &sealingStaging{Manager: sm}
	if seal {
		ss.onFirstUpdate = func() {
			// commit (phase 1): seal t1, give the branch a fresh token t2
			refs.Branch = &graveler.Branch{StagingToken: "t2", SealedTokens: []graveler.StagingToken{"t1"}}
			refs.StagingToken = "t2"
			refs.SealedTokens = []graveler.StagingToken{"t1"}
			if other {
				require.NoError(t, sm.Set(ctx, "t2", graveler.Key("obj"), &graveler.Value{Identity: []byte(otherIdentity), Data: []byte("data-2")}, false))
			}
		}
	}
	g := newGraveler(t, &testutil.CommittedFake{}, ss, refs, nil, testutil.NewProtectedBranchesManagerFake())
	val := graveler.Value{Identity: []byte("id-1"), Data: []byte("data-1")}
	err := g.Set(ctx, repository, "branch-1", graveler.Key("obj"), val, graveler.WithCondition(ifAbsent))
	written, gerr := sm.Get(ctx, "t1", graveler.Key("obj"))
	require.NoError(t, gerr)
	return err, written
}

func TestIfNoneMatch_NoCommit(t *testing.T) {
	err, written := runIfNoneMatch(t, false, false)
	require.NoError(t, err)
	require.Equal(t, "id-1", string(written.Identity))
}

// The write landed, so Set succeeds. Stock v1.86.0 fails with
// ErrPreconditionFailed here.
func TestIfNoneMatch_CommitSealsBetweenWriteAndRecheck(t *testing.T) {
	err, written := runIfNoneMatch(t, true, false)
	require.Equal(t, "id-1", string(written.Identity), "object was written to t1 (now sealed)")
	require.NoError(t, err, "client gets an error although its object was written")
}

// Another writer's value is not ours, so the retry still refuses it.
func TestIfNoneMatch_RetryStillRefusesAnotherWriter(t *testing.T) {
	err, _ := runIfNoneMatch(t, true, true)
	require.ErrorIs(t, err, graveler.ErrPreconditionFailed)
}

// Another writer's value with the same identity, the same content at another
// physical address, is still not ours, so the retry refuses it.
func TestIfNoneMatch_RetryRefusesTheSameContentFromAnotherWriter(t *testing.T) {
	err, _ := runIfNoneMatchWith(t, true, true, "id-1")
	require.ErrorIs(t, err, graveler.ErrPreconditionFailed)
}
