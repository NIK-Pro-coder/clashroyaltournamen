import json
import os
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Iterable

from dotenv import load_dotenv

load_dotenv()

KEY = os.getenv("API_KEY")

TEST_TAG = "VPGQ90UCR"


SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8080


class Response:
    def __init__(self) -> None:
        self.status_code: int = -1
        self.headers: list[tuple[str, str]] = []
        self.content: bytes = b""

    def setStatus(self, code: int):
        self.status_code = code
        return self

    def addHeader(self, name: str, value: str):
        self.headers.append((name, value))
        return self

    def write(self, what: str | bytes):
        if type(what) is str:
            self.content += bytes(what, "utf-8")
        elif type(what) is bytes:
            self.content += what
        return self

    def setType(self, tp: str):
        self.addHeader("Content-Type", tp)
        return self

    @staticmethod
    def Success():
        return Response().setStatus(200)

    @staticmethod
    def NotFound():
        return Response().setStatus(404)

    @staticmethod
    def BadRequest():
        return Response().setStatus(400)

    @staticmethod
    def Unauthorized():
        return Response().setStatus(401)

    @staticmethod
    def SeeOther():
        return Response().setStatus(303)


class Pageinfo:
    def __init__(
        self,
        fn: Callable[..., Response],
    ) -> None:
        self.resolver = fn


class MyServer(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server) -> None:
        self.params: dict[str, str] = {}
        super().__init__(request, client_address, server)

    def sendResponse(self, resp: Response):
        self.send_response(resp.status_code)

        for i in resp.headers:
            self.send_header(i[0], i[1])

        self.end_headers()

        self.wfile.write(resp.content)

    def getPath(self):
        return self.path[: self.path.find("?")] if "?" in self.path else self.path

    def getBody(self):
        body = {}

        for i in self.headers:
            if i == "Content-Length":
                raw = self.rfile.read(int(self.headers["Content-Length"])).decode()

                body = json.loads(raw)

        if "?" not in self.path:
            return body

        raw = self.path[self.path.find("?") + 1 :]

        for i in raw.split("&"):
            if "=" not in i:
                body[i] = None
                continue

            k, _, v = i.partition("=")

            body[k] = v

        return body

    def captureParams(self, path: str):
        s_req = self.path.split("/")
        s_path = path.split("/")

        self.params = {}

        for r, p in zip(s_req, s_path):
            if p.startswith(":"):
                self.params[p.removeprefix(":")] = r

    def matchPath(self, paths: Iterable[str]):
        split_path = self.path.split("/")

        for i in paths:
            s = i.split("/")

            if len(split_path) != len(s):
                continue

            if all(
                split_path[x] == s[x] or s[x].startswith(":")
                for x in range(len(split_path))
            ):
                self.captureParams(i)

                return i

        return None

    def handleRequest(self, paths: dict[str, Pageinfo]):
        path = self.matchPath(paths)

        if path is None:
            with open("notfound.html") as f:
                content = f.read()

            self.sendResponse(Response.NotFound().setType("text/html").write(content))

            return

        info = paths[path]

        argnum = info.resolver.__code__.co_argcount

        if argnum == 1:
            # Pass the reqeust to the resolver
            self.sendResponse(info.resolver(self))
        else:
            self.sendResponse(info.resolver())

    def do_GET(self):
        self.handleRequest(getPaths)

    def do_POST(self):
        self.handleRequest(postPaths)


getPaths: dict[str, Pageinfo] = {}
postPaths: dict[str, Pageinfo] = {}


def exposeFileGet(
    path: str,
    *,
    override_path: str | None = None,
    override_type: str | None = None,
    fallback: str | None = None,
):
    p = override_path if override_path is not None else path

    if not os.path.exists(path):
        print(f"File not found {repr(path)}")

    tp = "text/html" if override_type is None else override_type

    def inner():
        with open(path) as f:
            cont = f.read()

        return Response.Success().setType(tp).write(cont)

    exposeFuncGet(p, inner)


def exposeFuncGet(
    path: str,
    func: Callable[..., Response],
):
    getPaths[path] = Pageinfo(func)


def exposeFuncPost(
    path: str,
    func: Callable[..., Response],
):
    postPaths[path] = Pageinfo(func)


def traverseJson(obj: dict | list, path: str):
    where: list[int | str] = [""]

    isint = False

    for i in path:
        if i == "]":
            continue

        if (i == "." or i == "[") and isint:
            where[-1] = int(where[-1])
            isint = False

        if i == ".":
            where.append("")
        elif i == "[":
            isint = True
            where.append("")
        elif type(where[-1]) is str:
            where[-1] += i

    if isint:
        where[-1] = int(where[-1])

    n: Any = obj

    try:
        for i in where:
            n = n[i]
    except (IndexError, KeyError):
        return None

    return n


def findNth(haystack: str, needle: str, n: int):
    start = haystack.find(needle)
    while start >= 0 and n > 1:
        start = haystack.find(needle, start + 1)
        n -= 1
    return start


def fillPattern(pattern: str, info: dict):
    n_pat = pattern.replace("\t", " ").replace("\n", " ")
    s_pat = [x for x in n_pat.split(" ") if x]

    if len(s_pat) >= 4 and s_pat[-4] == "for":
        l_space = findNth(n_pat, " ", n_pat.count(" ") - 3)
        rep = n_pat[:l_space].strip()

        name = s_pat[-3]
        inside = s_pat[-1]

        over = traverseJson(info, inside)

        val = ""

        if "," not in name:
            if type(over) is not list:
                return ""

            for i in over:
                info[name] = i
                val += fillTemplate(rep, info)
        else:
            k_name, v_name = name.split(",")[0], name.split(",")[1]

            if type(over) is not dict:
                return ""

            for i in over:
                info[k_name] = i
                info[v_name] = over[i]
                val += fillTemplate(rep, info)

        return val

    if len(s_pat) >= 2 and s_pat[-2] == "if":
        l_space = findNth(n_pat, " ", n_pat.count(" ") - 1)
        disp = n_pat[:l_space].strip()

        name = s_pat[-1]
        invert = name.startswith("!")

        over = name.removeprefix("!") if invert else name

        val = traverseJson(info, over)

        if type(val) is not bool:
            return ""

        if val != invert:
            return fillTemplate(disp, info)
        else:
            return ""

    return traverseJson(info, n_pat)


def fillTemplate(temp: str, info: dict):
    new = ""

    chars = (x for x in temp)

    try:
        while True:
            c = next(chars)

            if c != "$":
                new += c
                continue

            nx = next(chars)

            if nx != "{":
                new += nx
                continue

            depth = 1
            pattern = ""

            while depth > 0:
                n = next(chars)

                pattern += n

                if n == "{":
                    depth += 1
                if n == "}":
                    depth -= 1

            pattern = pattern.removesuffix("}").strip()

            val = fillPattern(pattern, info)

            new += str(val)

    except StopIteration:
        ...

    return new


if __name__ == "__main__":
    webServer = HTTPServer((SERVER_HOST, SERVER_PORT), MyServer)
    print("Web server started http://%s:%s" % (SERVER_HOST, SERVER_PORT))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        print()

    webServer.server_close()
    print("Web server stopped.")
    print("Stopping socket server")
