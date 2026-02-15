from pathlib import Path
import os


def start_pipeline(user_data):
    """
    Simple coordinator:
    1. Takes user data from cli
    2. IF skip_subdomains = True  → Pass [domain] directly to collector
       IF skip_subdomains = False → Call subdomains.py first, then collector
    3. Calls collector.py for URL collection
    4. Calls visitor.py for URL visiting (uses user threads)
    5. IF wordpress_enabled → Also runs WordPress scanner (uses fixed concurrency)
    6. Saves discovered subdomains to file
    """

    domain = user_data["domain"]
    skip_subdomains = user_data["skip_subdomains"]
    wordpress_enabled = user_data.get("wordpress_enabled", False)
    threads = user_data.get("threads", 70)
    config = user_data["config"]

    # ------------------------------------------
    # Cross-platform: Use current working directory
    # ------------------------------------------
    work_dir = Path.cwd()

    # ------------------------------------------
    # NEW: normalize www domain (conditional)
    # ------------------------------------------
    has_www = domain.startswith("www.")
    if has_www:
        main_domain = domain[4:]  # remove 'www.'
    else:
        main_domain = domain

    # Add threads to config for visitor
    config["threads"] = threads

    outputs = {
        "subdomains_file": None,
        "visited_urls_dir": None,
        "wordpress_results": None,
        "summary": {}
    }

    # ==========================================
    # STEP 1: Determine final domain list
    # ==========================================

    if skip_subdomains:
        print("[*] Skipping subdomain enumeration...")
        final_domains = [domain]
        root_domain = domain

        outputs["summary"]["subdomains_discovered"] = 0
        outputs["summary"]["total_domains"] = 1

    else:
        print("[*] Running subdomain enumeration...")
        print("Subdomain enumeration can take quite a long time. Feel free to grab a coffee or complete another task while this runs.")

        from .subdomains import passive_subdomain_enum

        # ------------------------------------------
        # CHANGE: use main_domain ONLY if www existed
        # ------------------------------------------
        if has_www:
            input_domains = [main_domain]
        else:
            input_domains = [domain]

        discovered = passive_subdomain_enum(input_domains, config)

        # Merge domains
        final_domains = list(set([domain] + discovered))
        root_domain = domain

        # ------------------------------------------
        # CHANGE: remove main_domain from final list
        # ONLY when www was present
        # ------------------------------------------
        if has_www and main_domain in final_domains:
            final_domains.remove(main_domain)

        # Save subdomains
        subdomains_file = work_dir / "subdomains_discovered.txt"

        with subdomains_file.open("w") as f:
            f.write(f"# Subdomains for {domain}\n")
            f.write(f"# Total discovered: {len(discovered)}\n")
            f.write(f"# Total (including root): {len(final_domains)}\n\n")

            f.write(f"{domain} (root)\n")
            for subdomain in sorted(discovered):
                if not (has_www and subdomain == main_domain):
                    f.write(f"{subdomain}\n")

        outputs["subdomains_file"] = subdomains_file
        outputs["summary"]["subdomains_discovered"] = len(discovered)
        outputs["summary"]["total_domains"] = len(final_domains)

    # ==========================================
    # STEP 2: URL Collection
    # ==========================================

    print("[*] Running URL collection...")

    from .collector import run_collection_pipeline
    collector_output_dir = run_collection_pipeline(final_domains, config)

    # ==========================================
    # STEP 3: URL Visiting
    # ==========================================

    print("[*] Running URL validation...")

    from .visitor import visit_urls

    wordpress_domains = [root_domain] if wordpress_enabled else None

    visitor_output_dir = visit_urls(
        input_dir=collector_output_dir,
        wordpress_enabled=wordpress_enabled,
        wordpress_domains=wordpress_domains,
        config=config
    )

    outputs["visited_urls_dir"] = visitor_output_dir

    wp_results = work_dir / "wordpress_results.txt"
    if wordpress_enabled and wp_results.exists():
        outputs["wordpress_results"] = wp_results
        with wp_results.open() as f:
            outputs["summary"]["wordpress_findings"] = sum(1 for l in f if l.strip())

    visited_count = 0
    if visitor_output_dir.exists():
        for file in visitor_output_dir.glob("*_visited.txt"):
            with file.open() as f:
                visited_count += sum(1 for l in f if l.strip())

    outputs["summary"]["visited_urls"] = visited_count

    return outputs


if __name__ == "__main__":
    print("[TEST MODE]\n")

    test_data = {
        "domain": "example.com",
        "skip_subdomains": False,
        "wordpress_enabled": False,
        "threads": 70,
        "config": {}
    }

    result = start_pipeline(test_data)

    print("\n[TEST RESULT]")
    print(result)
