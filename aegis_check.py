from aegis_prompt_helper import *
from aegis_retrieval import *
import re


def getProgFromResponse(resp: str):
    # "```\w*\s+([\s|\S]+)```"gm
    rex = re.compile(r"```\w*\s+([\s|\S]+)```")
    res = rex.findall(resp)
    if len(res) > 0:
        return "\n".join(res)
    else:
        return resp


def removeMarkdownFormat(prog: str):
    prog = getProgFromResponse(prog).strip()

    def escape_newlines_in_quotes(match):
        string = str(match.group(0))
        if '\\n' in string:
            return string
        return match.group(0).replace('\n', '\\n')

    prog = re.sub(
        r'"(.*?)"', escape_newlines_in_quotes, prog, flags=re.DOTALL)

    if prog.startswith("```"):
        prog = prog[prog.find("\n"):]
        if prog.endswith("```"):
            prog = prog[:prog.rfind("```")]
        return prog
    return prog


def checkBpftraceComplier(prog: str):
    prog = removeMarkdownFormat(prog)
    c = getZerorpcClient()
    res = c.checkBpftrace(prog)
    logger.info(f"checkBpftraceComplier:\n{prog}\nThe compiler result: {res}")
    return res
