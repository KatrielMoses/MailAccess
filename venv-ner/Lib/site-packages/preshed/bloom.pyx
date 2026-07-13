# cython: infer_types=True
# cython: cdivision=True
#
from murmurhash.mrmr cimport hash128_x86
import math
from array import array

cimport cython

from libcpp.vector cimport vector

try:
    import copy_reg
except ImportError:
    import copyreg as copy_reg


def calculate_size_and_hash_count(members, error_rate):
    """Calculate the optimal size in bits and number of hash functions for a
    given number of members and error rate.  
    """
    base = math.log(1 / (2 ** math.log(2)))
    bit_count = math.ceil((members * math.log(error_rate)) / base)
    hash_count = math.floor((bit_count / members) * math.log(2))
    return (bit_count, hash_count)


cdef class BloomFilter:
    """Bloom filter that allows for basic membership tests.
    
    Only integers are supported as keys.
    """
    def __init__(self, key_t size=(2 ** 10), key_t hash_funcs=23, uint32_t seed=0):
        self.mem = Pool()
        self.c_bloom = <BloomStruct*>self.mem.alloc(1, sizeof(BloomStruct))
        bloom_init(self.mem, self.c_bloom, hash_funcs, size, seed)

    @classmethod
    def from_error_rate(cls, members, error_rate=1E-4):
        params = calculate_size_and_hash_count(members, error_rate)
        return cls(*params)

    def add(self, key_t item):
        with cython.critical_section(self):
            bloom_add(self.c_bloom, item)

    def __contains__(self, key_t item):
        with cython.critical_section(self):
            return bloom_contains(self.c_bloom, item)

    # Requires external synchronization (e.g. a critical section)
    cdef inline bint contains(self, key_t item) noexcept nogil:
        return bloom_contains(self.c_bloom, item)

    def to_bytes(self):
        with cython.critical_section(self):
            return bloom_to_bytes(self.c_bloom)

    def from_bytes(self, bytes byte_string):
        with cython.critical_section(self):
            bloom_from_bytes(self.mem, self.c_bloom, byte_string)
            return self

    def _roundtrip(self):
        # Purely for testing, since this operation can't be done atomically
        # without holding a critical section the entire time.
        # Entering the same critical section recursively doesn't release it.
        # (see cpython commit 180d417)
        with cython.critical_section(self):
            self.from_bytes(self.to_bytes())


cdef bytes bloom_to_bytes(const BloomStruct* bloom):
    # local scratch buffer
    cdef vector[key_t] ret = vector[key_t]()
    ret.push_back(bloom.hcount)
    ret.push_back(bloom.length)
    ret.push_back(<key_t>bloom.seed)
    for i in range(bloom.length // sizeof(key_t)):
        ret.push_back(bloom.bitfield[i])
    # copy data in the scratch buffer into a new bytes object
    return (<char *>ret.data())[:3*sizeof(key_t) + bloom.length]


cdef void bloom_from_bytes(Pool mem, BloomStruct* bloom, bytes data):
    cdef char* c_data = data;
    cdef key_t* i_data = <key_t*>c_data;
    bloom.hcount = i_data[0]
    bloom.length = i_data[1]
    bloom.seed = <uint32_t>i_data[2]
    bloom.bitfield = <key_t*>mem.alloc(bloom.length // sizeof(key_t), sizeof(key_t))
    for i in range(bloom.length // sizeof(key_t)):
        bloom.bitfield[i] = i_data[3+i]


cdef void bloom_init(Pool mem, BloomStruct* bloom, key_t hcount, key_t length, uint32_t seed) except *:
    # size should be a multiple of the container size - round up
    if length % sizeof(key_t):
        length = math.ceil(length / sizeof(key_t)) * sizeof(key_t)
    bloom.length = length
    bloom.hcount = hcount
    bloom.bitfield = <key_t*>mem.alloc(length // sizeof(key_t), sizeof(key_t))
    bloom.seed = seed


# Instead of calling MurmurHash with a different seed for each hash function, this
# generates two initial hash values and then combines them to create the correct
# number of hashes. This technique is faster than just doing MurmurhHash
# repeatedly and has been shown to work as well as full hashing.

# For details see "Less Hashing, Same Performance: Building a Better Bloom
# Filter", Kirsch & Mitzenmacher.

# https://www.semanticscholar.org/paper/Less-hashing%2C-same-performance%3A-Building-a-better-Kirsch-Mitzenmacher/65c43afbfc064705bdc40d3473f32518e9306429
# The choice of seeds is arbitrary.


cdef void bloom_add(BloomStruct* bloom, key_t item) noexcept nogil:
    cdef key_t hv
    cdef key_t[2] keys
    cdef key_t one = 1 # We want this explicitly typed, because bits
    hash128_x86(&item, sizeof(key_t), 0, &keys)
    for hiter in range(bloom.hcount):
        hv = (keys[0] + (hiter * keys[1])) % bloom.length
        bloom.bitfield[hv // sizeof(key_t)] |= one << (hv % sizeof(key_t))


cdef bint bloom_contains(const BloomStruct* bloom, key_t item) noexcept nogil:
    cdef key_t hv
    cdef key_t[2] keys
    cdef key_t one = 1 # We want this explicitly typed, because bits
    hash128_x86(&item, sizeof(key_t), 0, &keys)
    for hiter in range(bloom.hcount):
        hv = (keys[0] + (hiter * keys[1])) % bloom.length
        if not (bloom.bitfield[hv // sizeof(key_t)] & one << (hv % sizeof(key_t))):
            return False
    return True


def pickle_bloom(BloomFilter bloom):
    return unpickle_bloom, (bloom.to_bytes(),)


def unpickle_bloom(byte_string):
    return BloomFilter().from_bytes(byte_string)


copy_reg.pickle(BloomFilter, pickle_bloom, unpickle_bloom)
