// Copyright the regclient contributors.
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

package reg

import (
	"github.com/regclient/regclient/types/ref"
)

// manCacheKey identifies a cached manifest.
// Child is the digest of the manifest itself. Parent is the digest of the index
// that referenced it during platform resolution and is empty for top-level
// and single-manifest requests. Binding the child to its parent index keeps a
// moved tag from combining one index generation's selection with another.
type manCacheKey struct {
	Registry   string
	Repository string
	Child      string
	Parent     string
}

func newManCacheKey(r ref.Ref, parent string) manCacheKey {
	return manCacheKey{
		Registry:   r.Registry,
		Repository: r.Repository,
		Child:      r.Digest,
		Parent:     parent,
	}
}
