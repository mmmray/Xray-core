//go:build wasm
// +build wasm

package internet

// Acquire lock
func (fl *FileLocker) Acquire() error {
	panic("unimplemented")
}

// Release lock
func (fl *FileLocker) Release() {
	panic("unimplemented")
}
