from functools import lru_cache
import re
import zerorpc
import sys
import shlex
import os
import subprocess
from timebudget import timebudget
from loguru import logger
from aegis_config import settings
import time
import tempfile


c_keywords = [
    "alignas",
    "alignof",
    "auto",
    "bool",
    "break",
    "case",
    "char",
    "const",
    "constexpr",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "false",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "nullptr",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "struct",
    "switch",
    "thread_local",
    "true",
    "typedef",
    "typeof",
    "typeof_unqual",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_BitInt",
    "_Bool",
    "_Complex",
    "_Decimal128",
    "_Decimal32",
    "_Decimal64",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
    "asm",
    "fortran",
    "char",
    "signed char",
    "unsigned char",
    "short",
    "short int",
    "signed short",
    "signed short int",
    "unsigned short",
    "unsigned short int",
    "int",
    "signed",
    "signed int",
    "unsigned",
    "unsigned int",
    "long",
    "long int",
    "signed long",
    "signed long int",
    "unsigned long",
    "unsigned long int",
    "long long",
    "long long int",
    "signed long long",
    "signed long long int",
    "unsigned long long",
    "unsigned long long int",
    "float",
    "double",
    "long double",
    "void",
    "bool",
    "ptrdiff_t",
    "size_t",
    "wchar_t",
    "wint_t",
    "nullptr_t",
    "max_align_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "int_least8_t",
    "int_least16_t",
    "int_least32_t",
    "int_least64_t",
    "uint_least8_t",
    "uint_least16_t",
    "uint_least32_t",
    "uint_least64_t",
    "int_fast8_t",
    "int_fast16_t",
    "int_fast32_t",
    "int_fast64_t",
    "uint_fast8_t",
    "uint_fast16_t",
    "uint_fast32_t",
    "uint_fast64_t",
    "intptr_t",
    "uintptr_t",
    "intmax_t",
    "uintmax_t",
    "NULL",
]


def checkName(name: str):
    if not name or len(name) <= 3 or name in c_keywords:
        return False
    return True


class RPC(object):
    def __init__(self):
        self.kernel_folder = settings["kernel-find"]["kernel-folder"]
        self.script_folder = settings["kernel-find"]["script-folder"]
        pass

    @lru_cache(maxsize=32768)
    def findCaller(self, name: str):
        if not name:
            return ""
        starttime = time.perf_counter()
        logger.info(f"{name}")
        arg = ["python3", "-u",
               f"{self.callgraph_script_path}", f"{self.callgraph_sqlite_path}", "caller", f"{name}"]
        p = subprocess.run(
            arg, timeout=20, capture_output=True, shell=False)
        logger.info(f"retval[{p.returncode}] cost {
                    (time.perf_counter() - starttime)*1000}ms")
        if p.returncode == 0:
            return p.stdout.decode()
        else:
            return p.stderr.decode()

    @lru_cache(maxsize=32768)
    def findCallee(self, name: str):
        if not name:
            return ""
        starttime = time.perf_counter()
        logger.info(f"{name}")
        arg = ["python3", "-u",
               f"{self.callgraph_script_path}", f"{self.callgraph_sqlite_path}", "callee", f"{name}"]
        p = subprocess.run(
            arg, timeout=20, capture_output=True, shell=False)
        logger.info(f"retval[{p.returncode}] cost {
                    (time.perf_counter() - starttime)*1000}ms")
        if p.returncode == 0:
            return p.stdout.decode()
        else:
            return p.stderr.decode()

    @lru_cache(maxsize=32768)
    def findStruct(self, name: str):
        if not checkName(name):
            return ""
        starttime = time.perf_counter()
        logger.info(f"{name}")
        arg = ["python3", "-u", f"{self.script_folder}/findstruct.py",
               f"{self.kernel_folder}", f"{name}"]
        p = subprocess.run(
            arg, timeout=20, capture_output=True, shell=False)
        logger.info(f"retval[{p.returncode}] cost {
                    (time.perf_counter() - starttime)*1000}ms")
        if p.returncode == 0:
            return p.stdout.decode()
        else:
            return p.stderr.decode()

    @lru_cache(maxsize=32768)
    def findDefine(self, name: str):
        if not checkName(name):
            return ""
        starttime = time.perf_counter()
        logger.info(f"{name}")
        arg = ["python3", "-u", f"{self.script_folder}/finddefine.py",
               f"{self.kernel_folder}", f"{name}"]
        p = subprocess.run(
            arg, timeout=20, capture_output=True, shell=False)
        logger.info(f"retval[{p.returncode}] cost {
                    (time.perf_counter() - starttime)*1000}ms")
        if p.returncode == 0:
            return p.stdout.decode()
        else:
            return p.stderr.decode()

    @lru_cache(maxsize=32768)
    def findFunc(self, name: str):
        if not checkName(name):
            return ""
        starttime = time.perf_counter()
        logger.info(f"{name}")
        arg = ["python3", "-u", f"{self.script_folder}/findfunc.py",
               f"{self.kernel_folder}", f"{name}"]
        p = subprocess.run(
            arg, timeout=20, capture_output=True, shell=False)
        logger.info(f"retval[{p.returncode}] cost {
                    (time.perf_counter() - starttime)*1000}ms")
        if p.returncode == 0:
            return p.stdout.decode()
        else:
            return p.stderr.decode()

    def echo(self, msg: str):
        logger.info(f"{msg}")
        return msg

    def checkBpftraceProbes(self, prog: str):
        if not prog or len(prog) < 5:
            logger.warning("Prog in empty!")
            return "Prog in empty!"

        regex = re.compile(r'\w+:[\w|:|\/]+')
        res = regex.findall(prog)

        probes = "{}\n".join(res)
        probes += "{}\n"

        with tempfile.NamedTemporaryFile(delete_on_close=False) as fp:
            fp.write(probes.encode())
            fp.close()

            logger.info(f"{fp.name}:  {probes}")
            # the file is closed, but not removed
            # open the file again by using its name
            # with open(fp.name, mode='rb') as f:
            #     f.read()

            arg = ["bpftrace", f"{fp.name}"]
            try:
                p = subprocess.run(
                    arg, timeout=5, capture_output=True, shell=False)
                output = p.stderr.decode()
            except subprocess.TimeoutExpired:
                return "TIMEOUT"

            if "ERROR" in output:
                return output

            logger.warning(f"SHOULD NOT REACH HERE: {output}")
            return "PASS"

        # file is now removed since it exits from `with`
    def checkBpftrace(self, prog: str):
        if not prog or len(prog) < 5:
            logger.warning("Prog in empty!")
            return "Prog in empty!"
        with tempfile.NamedTemporaryFile(delete_on_close=False) as fp:
            fp.write(prog.encode())
            fp.close()

            logger.info(f"{fp.name}:  {prog}")
            # the file is closed, but not removed
            # open the file again by using its name
            # with open(fp.name, mode='rb') as f:
            #     f.read()

            myenv = os.environ.copy()
            myenv['BPFTRACE_LOG_SIZE'] = "33554432"
            arg = ["bpftrace", "-d", "--unsafe", f"{fp.name}"]
            p = subprocess.run(
                arg, timeout=30, capture_output=True, shell=False, env=myenv)
            if p.returncode == 0:
                res = self.checkBpftraceProbes(prog)
                if "PASS" in res or "TIMEOUT" in res:
                    return "PASS"
                else:
                    return res
            else:
                errmsg = p.stderr.decode()
                if "ERROR: bpftrace currently only supports running as the root user" in errmsg:
                    logger.error("Should run as root")

                return errmsg

        # file is now removed since it exits from `with`


def serverRun():
    s = zerorpc.Server(RPC())
    try:
        s.bind("tcp://0.0.0.0:24242")
    except Exception as e:
        logger.error(f"server start failed: {e}")
        logger.error(
            r"kill -9 $(lsof -i tcp:24242 |grep LISTEN |awk '{print $2}')")
        sys.exit(1)

    logger.info(f"server pid[{os.getpid()}] start at tcp://0.0.0.0:24242")
    s.run()


def clientRun():
    c = zerorpc.Client(timeout=60)
    c.connect("tcp://127.0.0.1:24242")

    if len(sys.argv) < 4:
        while True:
            try:
                msg = input().strip()
                sps = msg.split()
                if len(sps) < 2:
                    logger.warning(
                        f"Usage: [echo|struct|define|func|caller|callee] name")
                    continue
                comm = sps[0]
                name = sps[1]
                if comm == "echo":
                    print(c.echo(name))
                elif comm == "struct":
                    print(c.findStruct(name))
                elif comm == "define":
                    print(c.findDefine(name))
                elif comm == "func":
                    print(c.findFunc(name))
                elif comm == "caller":
                    print(c.findCaller(name))
                elif comm == "callee":
                    print(c.findCallee(name))
                else:
                    logger.warning(
                        f"Usage: [echo|struct|define|func|caller|callee] name")
            except:
                break
    else:
        comm = sys.argv[2]
        name = sys.argv[3]
        if comm == "echo":
            print(c.echo(name))
        elif comm == "struct":
            print(c.findStruct(name))
        elif comm == "define":
            print(c.findDefine(name))
        elif comm == "func":
            print(c.findFunc(name))
        elif comm == "caller":
            print(c.findCaller(name))
        elif comm == "callee":
            print(c.findCallee(name))
        else:
            logger.warning(
                f"Usage: [echo|struct|define|func|caller|callee] name")


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print("Usage: python rpc.py [server|client]", file=sys.stderr)
        sys.exit(1)
    if sys.argv[1] == "server":
        # logger.add("file_{time}.log", enqueue=True)
        serverRun()
    elif sys.argv[1] == "client":
        timebudget.set_quiet()  # don't show measurements as they happen
        clientRun()
        # timebudget.report_at_exit()  # Generate report when the program exits
    else:
        print("Usage: python rpc.py [server|client]")
