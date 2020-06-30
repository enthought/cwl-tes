"""FTP support"""
from __future__ import absolute_import

import contextlib
import fnmatch
import ftplib
import pycurl
import logging
import netrc
import glob
import os
from typing import List, Text  # noqa F401 # pylint: disable=unused-import

from six import PY2
from six.moves import urllib
from schema_salad.ref_resolver import uri_file_path
from typing import Tuple, Optional
from tempfile import NamedTemporaryFile
from contextlib import contextmanager

from cwltool.stdfsaccess import StdFsAccess
from cwltool.loghandler import _logger


@contextmanager
def use_and_delete(fname, mode='r'):
    '''
    Acquires resource, suspends operation and yields it to caller. When
    caller leaves its with-context, remaining resources are cleaned up.
    '''
    try:
        with open(fname, mode=mode) as fp:
            yield fp
    finally:
        os.unlink(fname)


def abspath(src, basedir):  # type: (Text, Text) -> Text
    """http(s):, file:, ftp:, and plain path aware absolute path"""
    scheme = urllib.parse.urlparse(src).scheme
    if scheme == u"file":
        apath = Text(uri_file_path(str(src)))
    elif scheme:
        return src
    else:
        if basedir.startswith(u"file://"):
            apath = src if os.path.isabs(src) else basedir + '/' + src
        else:
            apath = src if os.path.isabs(src) else os.path.join(basedir, src)
    return apath


class FtpFsAccess(StdFsAccess):
    """FTP access with upload."""
    def __init__(self, basedir, cache=None, insecure=False):  # t:(Text)->None
        super(FtpFsAccess, self).__init__(basedir)
        self.cache = cache or {}
        self.netrc = None
        self.insecure = insecure
        try:
            if 'HOME' in os.environ:
                if os.path.exists(os.path.join(os.environ['HOME'], '.netrc')):
                    self.netrc = netrc.netrc(
                        os.path.join(os.environ['HOME'], '.netrc'))
            elif os.path.exists(os.path.join(os.curdir, '.netrc')):
                self.netrc = netrc.netrc(os.path.join(os.curdir, '.netrc'))
        except netrc.NetrcParseError as err:
            _logger.debug(err)

    def _parse_url(self, url):
        # type: (Text) -> Tuple[Optional[Text], Optional[Text]]
        parse = urllib.parse.urlparse(url)
        user = parse.username
        passwd = parse.password
        host = parse.hostname
        path = parse.path
        if parse.scheme == 'ftp':
            if not user and self.netrc:
                creds = self.netrc.authenticators(host)
                if creds:
                    user, _, passwd = creds
        if not user:
            user, passwd = self._recall_credentials(host)
            if passwd is None:
                passwd = "anonymous@"
                if user is None:
                    user = "anonymous"

        return host, user, passwd, path

    def _connect(self, url):  # type: (Text) -> Optional[ftplib.FTP]
        parse = urllib.parse.urlparse(url)
        if parse.scheme == 'ftp':
            host, user, passwd, _ = self._parse_url(url)
            if (host, user, passwd) in self.cache:
                if self.cache[(host, user, passwd)].pwd():
                    return self.cache[(host, user, passwd)]
            ftp = ftplib.FTP_TLS()
            ftp.set_debuglevel(1 if _logger.isEnabledFor(logging.DEBUG) else 0)
            ftp.connect(host)
            ftp.login(user, passwd, secure=not self.insecure)
            self.cache[(host, user, passwd)] = ftp
            return ftp
        return None

    def _abs(self, p):  # type: (Text) -> Text
        return abspath(p, self.basedir)

    def _recall_credentials(self, desired_host):
        for host, user, passwd in self.cache:
            if desired_host == host:
                return user, passwd
        return None, None

    def glob(self, pattern):  # type: (Text) -> List[Text]
        if not self.basedir.startswith("ftp:"):
            return super(FtpFsAccess, self).glob(pattern)
        return self._glob(pattern)

    def _glob0(self, basename, basepath):
        if basename == '':
            if self.isdir(basepath):
                return [basename]
        else:
            if self.isfile(self.join(basepath, basename)):
                return [basename]
        return []

    def _glob1(self, pattern, basepath=None):
        try:
            names = self.listdir(basepath)
        except ftplib.all_errors:
            return []
        if pattern[0] != '.':
            names = filter(lambda x: x[0] != '.', names)
        return fnmatch.filter(names, pattern)

    def _glob(self, pattern):  # type: (Text) -> List[Text]
        if pattern.endswith("/."):
            pattern = pattern[:-1]
        dirname, basename = pattern.rsplit('/', 1)
        if not glob.has_magic(pattern):
            if basename:
                if self.exists(pattern):
                    return [pattern]
            else:  # Patterns ending in slash should match only directories
                if self.isdir(dirname):
                    return [pattern]
            return []
        if not dirname:
            return self._glob1(basename)

        dirs = self._glob(dirname)
        if glob.has_magic(basename):
            glob_in_dir = self._glob1
        else:
            glob_in_dir = self._glob0
        results = []
        for dirname in dirs:
            results.extend(glob_in_dir(basename, dirname))
        return results

    def open(self, fn, mode):
        if not fn.startswith("ftp:"):
            return super(FtpFsAccess, self).open(fn, mode)
        if 'r' in mode:
            host, user, passwd, path = self._parse_url(fn)
            url = "ftp://{}:{}@{}/{}".format(user, passwd, host, path)
            # Get FTP file handle by temporarily downloading file
            with NamedTemporaryFile(mode='wb', delete=False) as dest:
                c = pycurl.Curl()
                c.setopt(c.URL, url)
                c.setopt(c.WRITEDATA, dest)
                c.perform()
                response_code = c.getinfo(c.RESPONSE_CODE)
                if not (200 <= response_code <= 299):
                    print("There was a problem downloading " +
                          f"{c.getinfo(c.EFFECTIVE_URL)} ({response_code})")
                c.close()
                temp_fname = dest.name

            # Return a file handle in read mode
            handle = use_and_delete(temp_fname, mode)
            if PY2:
                return contextlib.closing(handle)
            return handle
        raise Exception('Write mode FTP not implemented')

    def exists(self, fn):  # type: (Text) -> bool
        if not self.basedir.startswith("ftp:"):
            return super(FtpFsAccess, self).exists(fn)
        return self.isfile(fn) or self.isdir(fn)

    def isfile(self, fn):  # type: (Text) -> bool
        ftp = self._connect(fn)
        if ftp:
            try:
                self.size(fn)
                return True
            except ftplib.all_errors:
                return False
        return super(FtpFsAccess, self).isfile(fn)

    def isdir(self, fn):  # type: (Text) -> bool
        ftp = self._connect(fn)
        if ftp:
            try:
                cwd = ftp.pwd()
                ftp.cwd(urllib.parse.urlparse(fn).path)
                ftp.cwd(cwd)
                return True
            except ftplib.all_errors:
                return False
        return super(FtpFsAccess, self).isdir(fn)

    def mkdir(self, url, recursive=True):
        """Make the directory specified in the URL."""
        ftp = self._connect(url)
        path = urllib.parse.urlparse(url).path
        if not recursive:
            return ftp.mkd(path)
        dirs = [d for d in path.split('/') if d != '']
        for index, _ in enumerate(dirs):
            try:
                ftp.mkd("/".join(dirs[:index+1])+'/')
            except ftplib.all_errors:
                pass
        return None

    def listdir(self, fn):  # type: (Text) -> List[Text]
        ftp = self._connect(fn)
        if ftp:
            host, username, passwd, path = self._parse_url(fn)
            if username != "anonymous":
                template = "ftp://{un}:{pw}@{0}/{1}"
            else:
                template = "ftp://{0}/{1}"
            return [template.format(host, item, un=username, pw=passwd)
                    for item in ftp.nlst(path)]
        return super(FtpFsAccess, self).listdir(fn)

    def join(self, path, *paths):  # type: (Text, *Text) -> Text
        if path.startswith('ftp:'):
            result = path
            for extra_path in paths:
                if extra_path.startswith('ftp:/'):
                    result = extra_path
                else:
                    result = result + "/" + extra_path
            return result
        return super(FtpFsAccess, self).join(path, *paths)

    def realpath(self, path):  # type: (Text) -> Text
        if path.startswith('ftp:'):
            return path
        return os.path.realpath(path)

    def size(self, fn):
        host, user, passwd, path = self._parse_url(fn)
        url = "ftp://{}:{}@{}/{}".format(user, passwd, host, path)
        try:
            c = pycurl.Curl()
            c.setopt(c.URL, url)

            # Tell curl not to echo the downloaded contents to stdout. The
            # second argument must be a function that accepts a bytes argument,
            # stores it in a buffer, and returns the number of bytes
            # written. Since we don't want to keep the contents around, the len
            # function works perfectly.
            c.setopt(c.WRITEFUNCTION, len)
            c.perform()
            return int(c.getinfo(c.CONTENT_LENGTH_DOWNLOAD))
        except Exception:
            return super(FtpFsAccess, self).size(fn)

    def upload(self, file_handle, url):
        """FtpFsAccess specific method to upload a file to the given URL."""
        c = pycurl.Curl()
        c.setopt(pycurl.URL, url)
        c.setopt(pycurl.VERBOSE, 1)
        c.setopt(pycurl.INFILE, file_handle)
        c.setopt(pycurl.UPLOAD, 1)
        c.perform()
        response_code = c.getinfo(c.RESPONSE_CODE)
        if not (200 <= response_code <= 299):
            print("There was a problem uploading " +
                  f"{c.getinfo(c.EFFECTIVE_URL)} ({response_code})")
        c.close()

    def download(self, file_handle, url):
        """FtpFsAccess specific method to download a file to the given URL."""
        c = pycurl.Curl()
        c.setopt(c.URL, url)
        c.setopt(c.WRITEDATA, file_handle)
        c.perform()
        response_code = c.getinfo(c.RESPONSE_CODE)
        if not (200 <= response_code <= 299):
            print("There was a problem downloading " +
                  f"{c.getinfo(c.EFFECTIVE_URL)} ({response_code})")
        c.close()
