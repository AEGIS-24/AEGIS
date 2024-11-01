
from aegis_prompt_helper import *
from functools import lru_cache
import pickle
from thefuzz import fuzz, process
import zerorpc
import re


@lru_cache
def getProbesDict():
    with open(settings['probes-pickle-path'], "rb") as f:
        probes = pickle.load(f)
    return probes

# Find possible eBPF probes based on function name or system call name


@lru_cache
def findProbe(name: str):
    probes = getProbesDict()
    keyslist = list(probes.keys())
    ans = process.extractOne(name, keyslist, scorer=fuzz.ratio)
    return ans


def findPossibleProbes(namelist: list):
    anslist = []
    probes = getProbesDict()

    for name in namelist:
        name = name.strip()
        if len(name) <= 2:
            continue
        probnames = [name, f"do_sys_{name}",
                     f"sys_enter_{name}", f"sys_exit_{name}"]

        for probname in probnames:
            ans = findProbe(probname)
            if not ans:
                continue
            # ('do_sys_open', 100)
            if ans[1] == 100:
                anslist.append(ans[0])
                break
            elif ans[1] > 70:
                anslist.append(ans[0])

    ans = []
    for shortname in anslist:
        ans.append(probes[shortname])
# [[('kfunc:vmlinux:do_sys_open', 'int dfd\nconst char * filename\nint flags\numode_t mode\nlong int retval'), ('kprobe:do_sys_open', ''), ('kretfunc:vmlinux:do_sys_open', 'int dfd\nconst char * filename\nint flags\numode_t mode\nlong int retval'), ('kretprobe:do_sys_open', '')]]
    return ans

# Finding function definition implementations by function name


@lru_cache
def getZerorpcClient():
    c = zerorpc.Client(timeout=60)
    c.connect("tcp://127.0.0.1:24242")
    return c


def checkZerorpc():
    try:
        c = getZerorpcClient()
        return c.echo("hello") == "hello"
    except Exception as e:
        logger.error(e)
        return False


def findFunctionDefinition(namelist: list):
    c = getZerorpcClient()
    ans = []
    logger.info(f"{namelist}")
    for name in namelist:
        ret = c.findFunc(name.strip())
        if ret:
            if len(ret) > 3000:
                logger.warning(f"[{name}] ret is too long:\n{len(ret)}")
                ret = ret[:3000]
            ans.append(ret)

    for name in namelist:
        if re.match(r'^[A-Z_]+$', name.strip()):
            ret = c.findDefine(name.strip())
            if ret:
                if len(ret) > 3000:
                    logger.warning(f"[{name}] ret is too long:\n{len(ret)}")
                    ret = ret[:3000]
                ans.append(ret)

    return ans


# Finding structure definitions by structure name
def findStructDefinition(namelist: list):
    c = getZerorpcClient()
    ans = []
    logger.info(f"{namelist}")
    for name in namelist:
        ret = c.findStruct(name.strip())
        if ret:
            if len(ret) > 3000:
                logger.warning(f"[{name}] ret is too long:\n{len(ret)}")
                ret = ret[:3000]
            ans.append(ret)
    return ans


# Finding the definition of a macro or enumeration value by name
def findMacroOrEnumDefinition(namelist: list):
    c = getZerorpcClient()
    ans = []
    logger.info(f"{namelist}")
    for name in namelist:
        ret = c.findDefine(name.strip())
        if ret:
            if len(ret) > 3000:
                logger.warning(f"[{name}] ret is too long:\n{len(ret)}")
                ret = ret[:3000]
            ans.append(ret)
    return ans
