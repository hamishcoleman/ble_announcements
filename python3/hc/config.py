import copy
import os
import yaml


def dict_merge(a, b):
    """Non destructively merge dict b into a"""
    for k, v in b.items():
        # trivial case: Doesnt exist in original, add it
        if k not in a:
            a[k] = copy.deepcopy(v)
            continue

        # Append new list items
        if isinstance(v, list):
            if isinstance(a[k], list):
                a[k] += v
                continue
            # Promote the old value to a list
            a[k] = [a[k]] + v
            continue

        # Recursively merge dicts
        if isinstance(v, dict):
            if isinstance(a[k], dict):
                dict_merge(a[k], v)
                continue
            # Dunno, could overwrite, but probably best to throw
            raise ValueError(f"Could not merge dict with non dict for {k}")

        # All others, simply overwrite
        a[k] = copy.deepcopy(v)


def dict_setpath(db, path, val):
    segs = path.split(".")
    for key in segs[:-1]:
        db = db.setdefault(key, {})

    db[segs[-1]] = val


def config_merge(config, filename):
    """Load a config file into the existing config"""

    if config.get("debug", False):
        print(f"Loading config file {filename}")

    fh = open(filename, "r")
    docs = yaml.safe_load_all(fh)

    for data in docs:
        if data is None:
            continue
        if not isinstance(data, dict):
            raise ValueError(f"Unexpected yaml data: {data}")

        dict_merge(config, data)


def config_name_resolve(name):
    """Convert directories into a list of config files"""

    if not os.path.isdir(name):
        return [name]

    names = []
    for entry in os.scandir(name):
        # Only process conf files
        if not entry.name.endswith(".conf"):
            continue
        # Dont recurse
        if entry.is_dir():
            continue

        names.append(entry.path)

    return names


def config_init(args, defaults):
    """load any conf files and merge the CLI args"""

    config = defaults
    config_files = []
    if args.config:
        for name in args.config:
            config_files.extend(config_name_resolve(name))

    for filename in config_files:
        config_merge(config, filename)

    # merge the cli args
    for opt in args.option:
        k, v = opt.split("=")

        dict_setpath(config, k, v)

    return config


def add_standard_args(args):
    args.add_argument(
        "--config",
        action="append",
        default=[],
        help="File(s) or dir(s) to load config settings from",
    )

    args.add_argument(
        "-O", "--option",
        action="append",
        default=[],
        help="Set a config option",
    )
