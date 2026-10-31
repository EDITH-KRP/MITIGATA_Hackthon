with open('src/cart/cli.py', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Imports
imp_target = 'from .orchestrator import Orchestrator'
imp_repl = '''from .attackpath import derive_run_relationships
from .orchestrator import Orchestrator
from .scope import setup_scope_for_target'''
if imp_target in text and 'setup_scope_for_target' not in text:
    text = text.replace(imp_target, imp_repl, 1)

# 2. cmd_select
sel_target = '''    print("=== Phase B: Organiser Scope Selection ===")
    prefix = args.prefix'''
sel_repl = '''    print("=== Phase B: Organiser Scope Selection ===")
    target_arg = getattr(args, "target", None)
    if target_arg:
        exclusions: list[str] = []
        if args.exclude:
            exclusions = [e.strip() for e in args.exclude.split(",") if e.strip()]
        binaries: dict[str, str] = {}
        if args.binaries:
            for b_path in args.binaries.split(","):
                bp = Path(b_path.strip())
                if bp.exists():
                    digest = hashlib.sha256(bp.read_bytes()).hexdigest()
                    binaries[str(bp)] = digest
        manifest, seed_url = setup_scope_for_target(
            conn, target_arg, exclusions=exclusions, binaries=binaries, created_by="organiser-cli"
        )
        print(f"\\n✅ Universal target `{target_arg}` scope locked as `{manifest.scope_version}`.")
        print("Ready to run: execute `cart run` to start the autonomous assessment.")
        return 0

    prefix = args.prefix'''
if sel_target in text:
    text = text.replace(sel_target, sel_repl, 1)

# 3. cmd_run
run_target = '''def cmd_run(args: argparse.Namespace) -> int:
    """Phase C-H: Fully autonomous assessment run within locked scope."""
    conn = _get_db(args.db)

    # Fetch latest locked scope manifest
    row = conn.execute(
        "SELECT scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at "
        "FROM scope_manifests WHERE locked_at IS NOT NULL ORDER BY locked_at DESC LIMIT 1"
    ).fetchone()

    if not row:
        print("❌ No locked scope manifest found! Please run `cart select` first.")
        return 1

    manifest = ScopeManifest(
        scope_version=row[0],
        included_prefixes=json.loads(row[1] or "[]"),
        included_hosts=json.loads(row[2] or "[]"),
        exclusions=json.loads(row[3] or "[]"),
        binary_hashes=json.loads(row[4] or "{}"),
        created_by=row[5],
        locked_at=row[6],
    )'''

run_repl = '''def cmd_run(args: argparse.Namespace) -> int:
    """Phase C-H: Fully autonomous assessment run within locked scope."""
    conn = _get_db(args.db)

    seed_url: str | None = None
    target_arg = getattr(args, "target", None)
    if target_arg:
        manifest, seed_url = setup_scope_for_target(conn, target_arg, created_by="organiser-cli")
        print(f"[*] Universal Target Configured: {target_arg}")
    else:
        # Fetch latest locked scope manifest
        row = conn.execute(
            "SELECT scope_version, included_prefixes, included_hosts, exclusions, binary_hashes, created_by, locked_at "
            "FROM scope_manifests WHERE locked_at IS NOT NULL ORDER BY locked_at DESC LIMIT 1"
        ).fetchone()

        if not row:
            print("❌ No locked scope manifest found! Please specify --target or run `cart select` first.")
            return 1

        manifest = ScopeManifest(
            scope_version=row[0],
            included_prefixes=json.loads(row[1] or "[]"),
            included_hosts=json.loads(row[2] or "[]"),
            exclusions=json.loads(row[3] or "[]"),
            binary_hashes=json.loads(row[4] or "{}"),
            created_by=row[5],
            locked_at=row[6],
        )'''
if run_target in text:
    text = text.replace(run_target, run_repl, 1)

# 4. Seed web task
seed_target = '''        orchestrator.create_task(t)

    for b_path in manifest.binary_hashes:'''
seed_repl = '''        orchestrator.create_task(t)

    if seed_url:
        t_web = Task(
            task_id=new_id("task"),
            task_type="web_crawl_endpoint_discovery",
            owner="web",
            target_id=seed_url,
            status=TaskStatus.READY,
            ptes_phase=PtesPhase.INTELLIGENCE_GATHERING,
            dedupe_key=f"{run_id}:web:{seed_url}",
            budget={"timeout_s": 300, "retries": 1},
        )
        orchestrator.create_task(t_web)

    for b_path in manifest.binary_hashes:'''
if seed_target in text:
    text = text.replace(seed_target, seed_repl, 1)

# 5. Derive relationships before report
ver_target = '''    ver_results = verifier.verify_all_queued()
    print(f"[*] Verified {len(ver_results)} findings.")

    # Final Report Generation'''
ver_repl = '''    ver_results = verifier.verify_all_queued()
    print(f"[*] Verified {len(ver_results)} findings.")

    # Derive evidence relationships for attack graph
    rel_count = derive_run_relationships(conn, run_id)
    print(f"[*] Constructed {rel_count} evidence-backed attack relationships.")

    # Final Report Generation'''
if ver_target in text:
    text = text.replace(ver_target, ver_repl, 1)

# 6. Parser options
arg_target = '''    p_select = sub.add_parser("select", help="Phase B: organiser selects lab, locks scope")
    p_select.add_argument("--prefix", help="Lab network CIDR prefix to select")'''
arg_repl = '''    p_select = sub.add_parser("select", help="Phase B: organiser selects lab, locks scope")
    p_select.add_argument("-t", "--target", help="Universal target URL, domain, IP, or CIDR to select and lock")
    p_select.add_argument("--prefix", help="Lab network CIDR prefix to select")'''
if arg_target in text:
    text = text.replace(arg_target, arg_repl, 1)

arg_target2 = '''    p_run = sub.add_parser("run", help="Phase C-H: autonomous run to final report")
    p_run.add_argument("--tier", default="recon", choices=["recon", "breach", "deep"], help="Assessment tier")'''
arg_repl2 = '''    p_run = sub.add_parser("run", help="Phase C-H: autonomous run to final report")
    p_run.add_argument("-t", "--target", help="Universal target URL, domain, IP, or CIDR to lock scope and assess immediately")
    p_run.add_argument("--tier", default="recon", choices=["recon", "breach", "deep"], help="Assessment tier")'''
if arg_target2 in text:
    text = text.replace(arg_target2, arg_repl2, 1)

with open('src/cart/cli.py', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text)
print('Successfully updated cli.py!')

