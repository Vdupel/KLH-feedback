"""GitHub Action в Vdupel/KLH-feedback (баг 025): всё незашифрованное — спрятать.

Issue или комментарий не в формате шифротекста KLH (старый клиент, отправка в обход программы с
извлечённым токеном, правка чужого issue) → содержимое шифруется тем же открытым ключом, что у
программы, и кладётся копией (не теряется — читает tools/feedback_decrypt.py), а оригинал удаляется:
  комментарий — DELETE (GITHUB_TOKEN; удаление убирает и историю правок);
  issue       — копия «Скрыто · <id>» новым issue, оригинал — GraphQL deleteIssue (нужен секрет
                FEEDBACK_ADMIN_TOKEN: права администратора репозитория). Без секрета — тело
                заменяется копией, issue закрывается и блокируется; история правок остаётся
                видна — поэтому секрет нужен.
Ничего из содержимого не исполняется: только проверка формата регулярными выражениями.
Запуск: .github/workflows/hide-unsealed.yml (рядом лежит feedback_crypto.py из KLH).
"""

from __future__ import annotations

import json
import os
import re
import secrets
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import feedback_crypto as fc  # noqa: E402  — в KLH-feedback: копия рядом
except ImportError:                # в KLH (тесты): оригинал
    from klh import feedback_crypto as fc  # noqa: E402

API = "https://api.github.com"
REPO = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["GITHUB_TOKEN"]
ADMIN = os.environ.get("FEEDBACK_ADMIN_TOKEN", "")

TITLE = re.compile(r"^(Ошибка|Идея|Скрыто) · [0-9a-f]{12}$")
BLOCK = r"```text\n[A-Za-z0-9+/=\n]+\n```\n?"
MARK = rf"<!-- {re.escape(fc.TAG)} id=(?P<id>[0-9a-f]{{12}}) part=(?P<n>\d+)/(?P<t>\d+) -->\n"
HEADER = (r"\*\*(Ошибка|Идея|Скрыто) · [0-9a-f]{12}\*\* — [^\n`<>\[\]()]{1,200}\n\n"
          r"(KLH `[0-9A-Za-z.\-?]{1,40}` · `[a-z?]{1,20}`|[^\n`<>\[\]()]{1,200})\n")
FIRST = re.compile(MARK + HEADER + BLOCK + r"\Z")
PART = re.compile(MARK + BLOCK + r"\Z")


def call(method: str, path: str, payload=None, token: str = TOKEN):
    req = urllib.request.Request(
        path if path.startswith("http") else f"{API}{path}",
        data=None if payload is None else json.dumps(payload).encode("utf-8"), method=method,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                 "User-Agent": "KLH-feedback-guard", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
    return json.loads(raw) if raw else {}


def valid_issue(issue: dict) -> bool:
    body = (issue.get("body") or "").replace("\r\n", "\n")
    m = FIRST.match(body)
    return bool(TITLE.match(issue.get("title") or "") and m and m.group("n") == "1"
                and m.group("id") in issue.get("title", ""))


def valid_comment(text: str) -> bool:
    m = PART.match((text or "").replace("\r\n", "\n"))
    return bool(m and int(m.group("n")) > 1)


def sealed_texts(kind: str, payload: dict) -> tuple[str, list[str]]:
    """Содержимое → (id, тексты частей) — как у программы, тип «Скрыто»."""
    hid = secrets.token_hex(6)
    fields = {"kind": "hidden", "id": hid, "title": f"скрыто: {kind}", "body": "",
              "meta": {"hidden": payload}}
    parts = fc.to_parts(fc.seal(fc.pack(fields, [])))
    header = (f"**Скрыто · {hid}** — пришло незашифрованным, спрятано автоматически.\n\n"
              "содержимое зашифровано, читают только разработчики")
    return hid, [fc.part_text(n, len(parts), hid, c, header if n == 1 else "")
                 for n, c in enumerate(parts, 1)]


def hide_comment(issue_no: int, comment: dict) -> None:
    hid, texts = sealed_texts("комментарий", {"issue": issue_no, "body": comment.get("body")})
    for t in texts:
        call("POST", f"/repos/{REPO}/issues/{issue_no}/comments", {"body": t})
    call("DELETE", f"/repos/{REPO}/issues/comments/{comment['id']}")
    print(f"комментарий {comment['id']} спрятан → {hid}")


def hide_issue(issue: dict) -> None:
    number = issue["number"]
    comments = call("GET", f"/repos/{REPO}/issues/{number}/comments?per_page=100")
    hid, texts = sealed_texts("issue", {"number": number, "title": issue.get("title"),
                                        "body": issue.get("body"),
                                        "comments": [c.get("body") for c in comments]})
    if ADMIN:
        copy = call("POST", f"/repos/{REPO}/issues",
                    {"title": f"Скрыто · {hid}", "body": texts[0], "labels": ["hidden"]})
        for t in texts[1:]:
            call("POST", f"/repos/{REPO}/issues/{copy['number']}/comments", {"body": t})
        call("POST", f"{API}/graphql", {
            "query": "mutation($id:ID!){deleteIssue(input:{issueId:$id}){clientMutationId}}",
            "variables": {"id": issue["node_id"]}}, token=ADMIN)
        print(f"issue #{number} удалён, копия #{copy['number']}")
        return
    call("PATCH", f"/repos/{REPO}/issues/{number}",
         {"title": f"Скрыто · {hid}", "body": texts[0], "state": "closed",
          "state_reason": "not_planned", "labels": ["hidden"]})
    for t in texts[1:]:
        call("POST", f"/repos/{REPO}/issues/{number}/comments", {"body": t})
    for c in comments:
        call("DELETE", f"/repos/{REPO}/issues/comments/{c['id']}")
    call("PUT", f"/repos/{REPO}/issues/{number}/lock", {"lock_reason": "spam"})
    print(f"issue #{number} спрятан на месте (нет FEEDBACK_ADMIN_TOKEN — история правок видна)")


def main() -> None:
    event = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
    name = os.environ.get("GITHUB_EVENT_NAME")
    issue = event.get("issue") or {}
    if name == "issues" and not valid_issue(issue):
        hide_issue(issue)
    elif name == "issue_comment" and not valid_comment((event.get("comment") or {}).get("body")):
        hide_comment(issue["number"], event["comment"])
    else:
        print("формат в порядке")


if __name__ == "__main__":
    main()
