#!/usr/bin/env python3
"""Parse and validate a mecmcp-family packaging/conformance.toml.

Emits shell-safe KEY=value lines for eval. Exits 2 on any invalid manifest,
so a typo cannot silently disable a rule.
"""
import sys
import tomllib

REQUIRED = {
    "binary": str, "installer": str, "service": str,
    "config_dir": str, "tokens": str,
    "build_info": bool, "units": list, "must_survive_override": list,
}
OPTIONAL = {"skip_build_env": (str, bool), "placeholders": dict}

# Keys whose value is resolved against the package staging directory by
# verify-package.sh. An absolute value is silently joined onto $STAGING there,
# which reports "not found" for a path that exists -- so reject it here with a
# message that says what is actually wrong.
STAGING_RELATIVE = ("binary", "installer")


def die(message):
    print(f"manifest error: {message}", file=sys.stderr)
    raise SystemExit(2)


def type_name(kind):
    if isinstance(kind, tuple):
        return " or ".join(one.__name__ for one in kind)
    return kind.__name__


def check_framing(where, value, forbid_tab=False):
    """Reject characters that would break the reader's own output framing.

    Scalar output is one KEY=value line per key and the caller assigns each
    line to a shell variable, so an embedded newline forges a second
    assignment -- a `tokens` value ending in "\\nCONF_BINARY=/bin/sh" would
    redirect R2 at a file that exists. List output is one item per line, and
    placeholder output is TOKEN<TAB>VALUE, so the same reasoning applies
    there.
    """
    if not isinstance(value, str):
        die(f"{where} must be a string (quote the value); got {type(value).__name__}")
    if "\n" in value or "\r" in value:
        die(
            f"{where} must not contain a newline. The reader emits one value "
            "per line and the caller assigns each line to a shell variable, "
            "so an embedded newline would forge a second assignment."
        )
    if forbid_tab and "\t" in value:
        die(f"{where} must not contain a tab; placeholders are emitted as TOKEN<TAB>VALUE")


def validate(data):
    unknown = set(data) - set(REQUIRED) - set(OPTIONAL)
    if unknown:
        die(f"unknown key(s): {', '.join(sorted(unknown))}")

    for key, kind in REQUIRED.items():
        if key not in data:
            die(f"missing required key: {key}")
        if not isinstance(data[key], kind):
            die(f"{key} must be {type_name(kind)}")

    # Optional keys were declared and never enforced, so `skip_build_env = true`
    # -- a bool -- satisfied the provenance ordering guard below while emitting
    # an EMPTY CONF_SKIP_BUILD_ENV, which silently disabled R3's rustc clause.
    for key, kind in OPTIONAL.items():
        if key in data and not isinstance(data[key], kind):
            die(f"{key} must be {type_name(kind)}")

    skip_build = data.get("skip_build_env", False)
    if skip_build is True:
        die(
            "skip_build_env = true is not a value. It must name the environment "
            "variable the packager honours to accept a prebuilt binary, e.g. "
            'skip_build_env = "SVC_SKIP_BUILD", or be false when the repo has no '
            "such path. A bare true satisfies the provenance ordering guard while "
            "naming nothing, which disables R3's rustc check."
        )
    if isinstance(skip_build, str):
        if not skip_build:
            die(
                'skip_build_env = "" is not a value. It must name the environment '
                "variable the packager honours to accept a prebuilt binary, or be "
                "false when the repo has no such path."
            )
        check_framing("skip_build_env", skip_build)

    for key in REQUIRED:
        if REQUIRED[key] is str:
            check_framing(key, data[key])

    for key in STAGING_RELATIVE:
        if data[key].startswith("/"):
            die(
                f"{key} must be a path inside the package staging directory, not "
                f"an absolute path: {data[key]}. verify-package.sh resolves it "
                "against --staging."
            )

    for name in ("units", "must_survive_override"):
        for index, item in enumerate(data[name]):
            check_framing(f"{name}[{index}]", item)
    for index, unit in enumerate(data["units"]):
        if unit.startswith("/"):
            die(
                f"units[{index}] must be a path inside the package staging "
                f"directory, not an absolute path: {unit}"
            )

    for token, value in data.get("placeholders", {}).items():
        check_framing(f"placeholder token {token!r}", token, forbid_tab=True)
        check_framing(f"placeholder value for {token!r}", value, forbid_tab=True)

    if data["build_info"] and not skip_build:
        die(
            "build_info = true requires skip_build_env. A repo with no supported "
            "way to package a CI-built binary cannot produce an honest BUILD-INFO, "
            "and demanding one is what produced the forged file in #355."
        )
    return skip_build


def main():
    if len(sys.argv) not in (2, 4) or (len(sys.argv) == 4 and sys.argv[2] != "--list"):
        die("usage: read-manifest.py <conformance.toml> [--list units|must_survive_override|placeholders]")
    try:
        with open(sys.argv[1], "rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        die(f"no such file: {sys.argv[1]}")
    except tomllib.TOMLDecodeError as error:
        die(f"not valid TOML: {error}")

    skip_build = validate(data)

    if len(sys.argv) == 4:
        name = sys.argv[3]
        if name == "placeholders":
            for token, value in data.get("placeholders", {}).items():
                print(f"{token}\t{value}")
        elif name in ("units", "must_survive_override"):
            for item in data[name]:
                print(item)
        else:
            die(f"unknown list: {name}")
        return

    # Scalars only. Lists are never squeezed through eval.
    print("\n".join([
        f"CONF_BINARY={data['binary']}",
        f"CONF_INSTALLER={data['installer']}",
        f"CONF_SERVICE={data['service']}",
        f"CONF_CONFIG_DIR={data['config_dir']}",
        f"CONF_TOKENS={data['tokens']}",
        f"CONF_BUILD_INFO={'true' if data['build_info'] else 'false'}",
        f"CONF_SKIP_BUILD_ENV={skip_build if isinstance(skip_build, str) else ''}",
    ]))


if __name__ == "__main__":
    main()
