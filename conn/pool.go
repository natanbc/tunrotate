package conn

import (
    "sync"
)

const bufferSize = 1 << 17

var _buffers = sync.Pool {
    New: func() interface {} {
        return make([]byte, bufferSize)
    },
}

func acquireBuffer() []byte {
    return _buffers.Get().([]byte)
}

func releaseBuffer(buf []byte) {
    _buffers.Put(buf)
}

