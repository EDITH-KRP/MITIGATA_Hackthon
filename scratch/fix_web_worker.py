with open('src/cart/workers/web.py', 'r', encoding='utf-8') as f:
    text = f.read()

target = '''        # Resolve asset → IP
        row = self.conn.execute(
            "SELECT canonical_key FROM assets WHERE asset_id=?", (task.target_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Asset {task.target_id} not found in store")
        ip = row[0]

        # Prefer a web port discovered and stored by NetworkWorker. This also
        # supports local lab apps exposed on non-privileged ports such as 8080.
        base_url = self._detect_base_url(ip, task.target_id)

        # SCOPE GATE on base URL before crawl starts
        gate_result = self.gate.gate(base_url, self.run_id, is_url=True)
        event = ToolEvent(
            event_id=new_id("evt"),
            task_id=task.task_id,
            tool="web_crawler",
            target=base_url,
            scope_decision=gate_result.decision,
            started_at=utc_now(),
        )
        if gate_result.decision is ScopeDecision.DENY:
            event.finished_at = utc_now()
            event.exit_status = "scope_denied"
            _persist_tool_event(self.conn, event)
            raise PermissionError(f"Scope DENY for {base_url}: {gate_result.reason}")

        all_base_urls = self._detect_all_base_urls(ip, task.target_id)'''

repl = '''        # Resolve asset → IP or direct seed URL
        if task.target_id.startswith(("http://", "https://")):
            base_url = task.target_id
            parsed = urllib.parse.urlparse(base_url)
            ip = parsed.hostname or base_url
            all_base_urls = [base_url]
        else:
            row = self.conn.execute(
                "SELECT canonical_key FROM assets WHERE asset_id=?", (task.target_id,)
            ).fetchone()
            if row is None:
                raise ValueError(f"Asset {task.target_id} not found in store")
            ip = row[0]
            base_url = self._detect_base_url(ip, task.target_id)
            all_base_urls = self._detect_all_base_urls(ip, task.target_id)

        # SCOPE GATE on base URL before crawl starts
        gate_result = self.gate.gate(base_url, self.run_id, is_url=True)
        event = ToolEvent(
            event_id=new_id("evt"),
            task_id=task.task_id,
            tool="web_crawler",
            target=base_url,
            scope_decision=gate_result.decision,
            started_at=utc_now(),
        )
        if gate_result.decision is ScopeDecision.DENY:
            event.finished_at = utc_now()
            event.exit_status = "scope_denied"
            _persist_tool_event(self.conn, event)
            raise PermissionError(f"Scope DENY for {base_url}: {gate_result.reason}")'''

assert target in text, 'target not found'
text = text.replace(target, repl, 1)

with open('src/cart/workers/web.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)

print('Updated WebWorker.run for direct URLs!')

