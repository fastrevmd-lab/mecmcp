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


def die(message):
    print(f"manifest error: {message}", file=sys.stderr)
    raise SystemExit(2)


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

    unknown = set(data) - set(REQUIRED) - set(OPTIONAL)
    if unknown:
        die(f"unknown key(s): {', '.join(sorted(unknown))}")
    for key, kind in REQUIRED.items():
        if key not in data:
            die(f"missing required key: {key}")
        if not isinstance(data[key], kind):
            die(f"{key} must be {kind.__name__}")

    skip_build = data.get("skip_build_env", False)
    if data["build_info"] and not skip_build:
        die(
            "build_info = true requires skip_build_env. A repo with no supported "
            "way to package a CI-built binary cannot produce an honest BUILD-INFO, "
            "and demanding one is what produced the forged file in #355."
        )

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
