import contextlib
import re
import tempfile

import srsly


@contextlib.contextmanager
def make_tempfile(mode="r"):
    f = tempfile.TemporaryFile(mode=mode)
    yield f
    f.close()


def assert_packed_msg_equal(b1, b2):
    """Assert that two packed msgpack messages are equal."""
    msg1 = srsly.msgpack_loads(b1)
    msg2 = srsly.msgpack_loads(b2)
    assert sorted(msg1.keys()) == sorted(msg2.keys())
    for (k1, v1), (k2, v2) in zip(sorted(msg1.items()), sorted(msg2.items())):
        assert k1 == k2
        assert v1 == v2


def normalize_whitespace(s):
    return re.sub(r"\s+", " ", s)
