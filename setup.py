import pathlib
import subprocess
import shutil
import re

from setuptools import setup, find_packages


def package_dependencies():
    module_dir = pathlib.Path(__file__).parent / "qtrace"
    deps_dir = module_dir / "deps"
    qemu_path = pathlib.Path("/usr/local/bin/qemu-x86_64")

    ldd_output = subprocess.check_output(["/usr/bin/ldd", qemu_path], encoding="ascii")
    qemu_dependencies = [pathlib.Path(e) for e in re.findall("/lib\S+", ldd_output)]

    libqtrace_path = module_dir.parent / "qemu_plugin" / "libqtrace.so"

    deps_dir.mkdir(parents=True, exist_ok=True)

    for path in [qemu_path, *qemu_dependencies]:
        module_relative_path = str(path)[1:]
        dst_path = deps_dir / module_relative_path
        dst_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(path, dst_path)
        yield f"deps/{module_relative_path}"

    shutil.copy(libqtrace_path, deps_dir / "libqtrace.so")
    yield "deps/libqtrace.so"


setup(
    name="qtrace",
    version="0.1.0",
    python_requires=">=3.6",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "qtrace = qtrace.__main__:main",
        ]
    },
    package_data={"qtrace": list(package_dependencies())},
)
