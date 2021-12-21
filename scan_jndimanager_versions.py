import os
from enum import Enum, auto
from optparse import OptionParser
from typing import IO
from zipfile import BadZipFile, ZipFile


JNDIMANAGER_CLASS_NAME = "log4j/core/net/JndiManager.class"
JNDILOOKUP_CLASS_NAME = "log4j/core/lookup/JndiLookup.class"
PATCH_STRING = b"allowedJndiProtocols"
PATCH_STRING_216 = b"log4j2.enableJndi"
PATCH_STRING_21 = b"LOOKUP"
PATCH_STRING_BACKPORT = b"JNDI is not supported"

RED = "\x1b[31m"
GREEN = "\x1b[32m"
RESET_ALL = "\x1b[0m"

verbose = False


class JndiManagerVersion(Enum):
    v20 = auto()
    v21_to_v214 = auto()
    v215 = auto()
    v216_OR_ABOVE = auto()
    v212_BACKPORT = auto()


def version_message(filename: str, version: JndiManagerVersion):
    if version in {JndiManagerVersion.v21_to_v214, JndiManagerVersion.v20}:
        print(f"{filename}: {RED}vulnerable JndiManager found{RESET_ALL}")
    elif version == JndiManagerVersion.v215:
        print(f"{filename}: {GREEN}fixed JndiManager found{RESET_ALL} (2.15)")
    elif version == JndiManagerVersion.v212_BACKPORT:
        print(f"{filename}: {GREEN}fixed JndiManager found{RESET_ALL} (backport)")
    elif version == JndiManagerVersion.v216_OR_ABOVE:
        print(f"{filename}: {GREEN}fixed JndiManager found{RESET_ALL}")


def old_jndilookup(classfile_content):
    return (PATCH_STRING_21 not in classfile_content) and (
        PATCH_STRING_BACKPORT not in classfile_content
    )


def class_version_jndi_manager(classfile_content):

    if PATCH_STRING in classfile_content:
        if PATCH_STRING_216 in classfile_content:
            return JndiManagerVersion.v216_OR_ABOVE
        return JndiManagerVersion.v215
    elif PATCH_STRING_216 in classfile_content:
        return JndiManagerVersion.v212_BACKPORT
    return JndiManagerVersion.v21_to_v214


def test_file(file: IO[bytes], rel_path: str):
    try:
        with ZipFile(file) as jarfile:
            for file_name in jarfile.namelist():
                # Recursively process nested jar files
                if acceptable_filename(file_name):
                    next_file = jarfile.open(file_name, "r")
                    test_file(next_file, os.path.join(rel_path, file_name))
                    continue

                if file_name.endswith(JNDIMANAGER_CLASS_NAME):
                    classfile_content = jarfile.read(file_name)
                    version_message(
                        rel_path, class_version_jndi_manager(classfile_content)
                    )
                    continue

                if file_name.endswith(JNDILOOKUP_CLASS_NAME):
                    classfile_content = jarfile.read(file_name)
                    if old_jndilookup(classfile_content):
                        version_message(rel_path, JndiManagerVersion.v20)

    except (IOError, BadZipFile):
        return


def acceptable_filename(filename):
    return filename.endswith(".jar") or filename.endswith(".ear") or filename.endswith(".sar") or filename.endswith(".war")


def run_scanner(root_dir: str):
    if os.path.isdir(root_dir):
        print("Scanning...")
        for directory, dirs, files in os.walk(root_dir):
            for filename in files:
                if acceptable_filename(filename):
                    full_path = os.path.join(directory, filename)
                    rel_path = os.path.relpath(full_path, root_dir)
                    if verbose:
                        print(rel_path)

                    try:
                        with open(full_path, "rb") as file:
                            test_file(file, rel_path)
                    except FileNotFoundError as fnf_error:
                        print(fnf_error)

    elif os.path.isfile(root_dir):
        if acceptable_filename(root_dir):
            with open(root_dir, "rb") as file:
                test_file(file, "")


if __name__ == "__main__":
    usage = "usage: %prog [options] <root_folder>"
    parser = OptionParser(usage=usage)
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Print all found java archive files")
    (options, args) = parser.parse_args()

    if len(args) != 1:
        parser.error("Missing argument for root folder to scan")

    verbose = options.verbose

    root_dir = args[0]

    if not os.path.isdir(root_dir):
        print("Given directory [" + root_dir + "] does not exist")
        exit(1)

    run_scanner(root_dir)
