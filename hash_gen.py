"""Generate md5, sha1, sha256 for string or file."""
import hashlib
import argparse
import os


def gen_str_sha1(str):
    """Generate string sha1."""
    sha1 = hashlib.sha1(str.encode(encoding='utf-8')).hexdigest()
    return sha1


def gen_str_sha256(str):
    """Generate string sha256."""
    sha256 = hashlib.sha256(str.encode(encoding='utf-8')).hexdigest()
    return sha256


def gen_str_md5(str):
    """Generate string md5."""
    md5 = hashlib.md5(str.encode(encoding='utf-8')).hexdigest()
    return md5


def gen_file_sha1(filepath):
    """Generate file sha1."""
    sha1 = hashlib.sha1()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha1.update(chunk)
    return sha1.hexdigest()


def gen_file_sha256(filepath):
    """Generate file sha256."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def gen_file_md5(filepath):
    """Generate file md5."""
    md5 = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
    return md5.hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hash generator")
    parser.add_argument('-f', '--func', default='md5',
                        help="Hash function: md5, sha1, sha256." +
                        "Default is md5.")
    parser.add_argument('input', help="input string or filepath")
    args = parser.parse_args()
    func = args.func
    obj = args.input
    input_type = 'file' if os.path.isfile(obj) else 'str'
    print(locals()["gen_" + input_type + '_' + func](obj))
