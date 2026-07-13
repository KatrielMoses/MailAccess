import os
import re
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Optional, TYPE_CHECKING

from ..cloudpath import CloudPath, NoStatError, register_path_class

if TYPE_CHECKING:
    from .s3client import S3Client

_MRAP_PATTERN = re.compile(
    r"^s3://(?P<arn>arn:aws:s3::\d{12}:accesspoint/[^/]+\.mrap)(?:/(?P<key>.*))?$"
)


@register_path_class("s3")
class S3Path(CloudPath):
    """Class for representing and operating on AWS S3 URIs, in the style of the Python standard
    library's [`pathlib` module](https://docs.python.org/3/library/pathlib.html). Instances
    represent a path in S3 with filesystem path semantics, and convenient methods allow for basic
    operations like joining, reading, writing, iterating over contents, etc. This class almost
    entirely mimics the [`pathlib.Path`](https://docs.python.org/3/library/pathlib.html#pathlib.Path)
    interface, so most familiar properties and methods should be available and behave in the
    expected way.

    The [`S3Client`](../s3client/) class handles authentication with AWS. If a client instance is
    not explicitly specified on `S3Path` instantiation, a default client is used. See `S3Client`'s
    documentation for more details.
    """

    cloud_prefix: str = "s3://"
    client: "S3Client"
    _bucket: str
    _local_path: Path

    @property
    def drive(self) -> str:
        return self.bucket

    def mkdir(self, parents=False, exist_ok=False, mode: Optional[Any] = None):
        # not possible to make empty directory on s3
        pass

    def touch(self, exist_ok: bool = True, mode: Optional[Any] = None):
        if self.exists():
            if not exist_ok:
                raise FileExistsError(f"File exists: {self}")
            self.client._move_file(self, self)
        else:
            tf = TemporaryDirectory()
            p = Path(tf.name) / "empty"
            p.touch()

            self.client._upload_file(p, self)

            tf.cleanup()

    def stat(self, follow_symlinks=True):
        try:
            meta = self.client._get_metadata(self)
        except self.client.client.exceptions.NoSuchKey:
            raise NoStatError(
                f"No stats available for {self}; it may be a directory or not exist."
            )

        return os.stat_result(
            (
                None,  # mode
                None,  # ino
                self.cloud_prefix,  # dev,
                None,  # nlink,
                None,  # uid,
                None,  # gid,
                meta.get("size", 0),  # size,
                None,  # atime,
                meta.get("last_modified", 0).timestamp(),  # mtime,
                None,  # ctime,
            )
        )

    @property
    def bucket(self) -> str:
        """The bucket name, or the full MRAP ARN for MRAP paths.

        :type: :class:`str`
        """
        if hasattr(self, "_bucket"):
            return self._bucket
        if match := _MRAP_PATTERN.match(str(self)):
            self._bucket = match.group("arn")
        else:
            self._bucket = self._no_prefix.split("/", 1)[0]
        return self._bucket

    @property
    def key(self) -> str:
        key = self._no_prefix_no_drive

        # key should never have starting slash for
        # use with boto, etc.
        if key.startswith("/"):
            key = key[1:]

        return key

    @property
    def etag(self):
        return self.client._get_metadata(self).get("etag")

    @property
    def _local(self) -> Path:
        if hasattr(self, "_local_path"):
            return self._local_path
        no_prefix = self._no_prefix
        # `:` is invalid in Windows paths; percent-encode it for MRAP ARNs
        if sys.platform == "win32":
            no_prefix = no_prefix.replace(":", "%3A")
        self._local_path = self.client._local_cache_dir / no_prefix
        return self._local_path
