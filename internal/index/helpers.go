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

package index

import "os"
import "path/filepath"

// helpers.go — tiny file utilities shared by the install path.

func joinPath(dir, name string) string {
	return filepath.Join(dir, name)
}

// writeFile0600 writes payload to path with the 0600 permission policy
// (creating the parent directory 0700 when needed).
func writeFile0600(path string, payload []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return errf(CodeState, "cannot create the index directory", err.Error(), "", err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return errf(CodeState, "cannot write "+filepath.Base(path), err.Error(), "", err)
	}
	return nil
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
