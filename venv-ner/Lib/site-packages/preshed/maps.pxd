from libc.stdint cimport uint64_t
from cymem.cymem cimport Pool


# Low-level thread-unsafe C API.
# If you use this API and expose it to Python, you must provide external
# synchronization (e.g. with a lock or critical section).

ctypedef uint64_t key_t


cdef struct Cell:
    key_t key
    void* value


cdef struct Result:
    int found
    void* value


cdef struct MapStruct:
    Cell* cells
    void* value_for_empty_key
    void* value_for_del_key
    key_t length
    key_t filled
    bint is_empty_key_set
    bint is_del_key_set

cdef void* map_bulk_get(const MapStruct* map_, const key_t* keys, void** values,
                        int n) noexcept nogil


cdef Result map_get_unless_missing(const MapStruct* map_, const key_t key) noexcept nogil

cdef void* map_get(const MapStruct* map_, const key_t key) noexcept nogil

cdef void map_set(Pool mem, MapStruct* map_, key_t key, void* value) except *

cdef void map_init(Pool mem, MapStruct* pmap, size_t length) except *

cdef bint map_iter(const MapStruct* map_, int* i, key_t* key, void** value) noexcept nogil

cdef void* map_clear(MapStruct* map_, const key_t key) noexcept nogil


cdef class PreshMap:
    cdef MapStruct* c_map
    cdef Pool mem

    # these methods are thread-unsafe and require external synchronization
    cdef inline void* get(self, key_t key) noexcept nogil
    cdef void set(self, key_t key, void* value) except *

# note: this class is thread-unsafe without external synchronization
cdef class PreshMapArray:
    cdef Pool mem
    cdef MapStruct* maps
    cdef size_t length

    cdef inline void* get(self, size_t i, key_t key) noexcept nogil
    cdef void set(self, size_t i, key_t key, void* value) except *
