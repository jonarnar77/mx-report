# mx_domain_analyzer.py
# A script to analyze domain MX records, SPF, DMARC, and DKIM settings.
#
# To run this script, you'll need to install the dnspython library:
# pip install dnspython

import argparse
import dns.resolver
import dns.reversename # Added for PTR lookups
import re
import json
import html # For HTML escaping

def get_mx_records(domain):
    """
    Fetches MX records for a given domain.
    Identifies if they point to Google Workspace or Microsoft 365.
    """
    records_info = {"records": [], "provider": "Other", "warnings": []}
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for rdata in sorted(mx_records, key=lambda r: r.preference):
            exchange = rdata.exchange.to_text(omit_final_dot=True).lower()
            records_info["records"].append({"preference": rdata.preference, "exchange": exchange})
            if "google.com" in exchange or "googlemail.com" in exchange:
                records_info["provider"] = "Google Workspace"
            elif "outlook.com" in exchange or "office365.com" in exchange:
                records_info["provider"] = "Microsoft 365"
    except dns.resolver.NXDOMAIN:
        records_info["warnings"].append(f"Domain {domain} not found (NXDOMAIN).")
    except dns.resolver.NoAnswer:
        records_info["warnings"].append(f"No MX records found for {domain}.")
    except dns.exception.Timeout:
        records_info["warnings"].append(f"DNS query timed out for MX records of {domain}.")
    except Exception as e:
        records_info["warnings"].append(f"An error occurred while fetching MX records: {e}")
    return records_info

def get_spf_record(domain):
    """
    Fetches and analyzes SPF records for a given domain, including reverse DNS for IPs.
    """
    spf_info = {"record": None, "parsed_components": [], "warnings": [], "recommendations": []}
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        spf_records_found = []
        for rdata in txt_records:
            for string in rdata.strings:
                txt_string = string.decode('utf-8')
                if txt_string.startswith("v=spf1"):
                    spf_records_found.append(txt_string)

        if not spf_records_found:
            spf_info["warnings"].append("No SPF record found.")
            spf_info["recommendations"].append("Consider adding an SPF record to prevent email spoofing.")
            return spf_info

        if len(spf_records_found) > 1:
            spf_info["warnings"].append(f"Multiple SPF records found. This is invalid and can cause issues. Found: {spf_records_found}")
            spf_info["recommendations"].append("Consolidate SPF mechanisms into a single TXT record.")
            # We'll analyze the first one found for now, despite the error
            spf_info["record"] = spf_records_found[0]
        else:
            spf_info["record"] = spf_records_found[0]

        # Detailed parsing of SPF components
        parts = spf_info["record"].split()
        if not parts or parts[0] != "v=spf1": # check if parts is empty
            spf_info["warnings"].append(f"SPF record does not start with 'v=spf1'. Found: {parts[0] if parts else 'empty record'}")
            # Attempt to parse anyway if possible, or return early if it's too malformed
            if not parts or len(parts) < 2 : return spf_info

        spf_info["parsed_components"].append({
            "raw": parts[0],
            "type": "version",
            "value": "spf1", # value is 'spf1' for version
            "qualifier": "", # No qualifier for version
            "explanation": "Specifies the SPF version (must be 'spf1')."
        })

        found_all_mechanism = False
        for part_str in parts[1:]:
            component = {"raw": part_str, "qualifier": "+", "type": "", "value": "", "explanation": ""}

            # Determine qualifier
            if part_str.startswith(("+", "-", "~", "?")):
                component["qualifier"] = part_str[0]
                mechanism_part = part_str[1:]
            else:
                mechanism_part = part_str # Default qualifier is '+'

            # Determine type and value
            if ":" in mechanism_part:
                m_type, m_value = mechanism_part.split(":", 1)
                component["type"] = m_type.lower()
                component["value"] = m_value
            else: # Mechanisms like 'a', 'mx', 'all'
                component["type"] = mechanism_part.lower()
                # For 'a' and 'mx' without explicit domain, value is current domain. For 'all', value is effectively its qualifier.
                component["value"] = domain if component["type"] in ["a", "mx"] and not component.get("value") else ""


            if component["type"] == "all":
                found_all_mechanism = True
                # The 'value' for 'all' type can be considered the qualifier itself or empty if we just rely on component['qualifier']
                component["value"] = "" # 'all' mechanism itself doesn't take a host/domain value. Its behavior is defined by qualifier.
                qualifier_for_all = component["qualifier"] if component["qualifier"] else "+" # if "all" is written without explicit qualifier

                if qualifier_for_all == "+":
                    component["explanation"] = "Mechanism 'all' with '+' qualifier (Pass): Allows any server. Highly discouraged due to security risks."
                    spf_info["warnings"].append("SPF 'all' mechanism is effectively '+all'. This is a security risk.")
                    spf_info["recommendations"].append("Change to '~all' (SoftFail) or '-all' (Fail).")
                elif qualifier_for_all == "-":
                    component["explanation"] = "Mechanism 'all' with '-' qualifier (Fail): Servers not explicitly permitted are rejected. Recommended for strict enforcement."
                elif qualifier_for_all == "~":
                    component["explanation"] = "Mechanism 'all' with '~' qualifier (SoftFail): Emails from unlisted servers should be marked as suspicious. Good practice."
                    spf_info["recommendations"].append("SPF 'all' mechanism is '~all' (SoftFail). Consider '-all' (Fail) for stricter policy if confident.")
                elif qualifier_for_all == "?":
                    component["explanation"] = "Mechanism 'all' with '?' qualifier (Neutral): Emails from unlisted servers are neither passed nor failed explicitly. Offers no protection."
                    spf_info["warnings"].append("SPF 'all' mechanism is effectively '?all'. This provides no protection.")
                    spf_info["recommendations"].append("Change to '~all' (SoftFail) or '-all' (Fail).")


            elif component["type"] == "include":
                component["explanation"] = f"Mechanism 'include:{component['value']}': Delegates to the SPF policy of '{component['value']}'. Mail is passed if the included policy passes."
            elif component["type"] == "a":
                target_domain = component['value'] if component['value'] else domain
                component["explanation"] = f"Mechanism 'a{':' + component['value'] if component['value'] else ''}': Allows mail from servers whose A/AAAA DNS records match '{target_domain}'."
            elif component["type"] == "mx":
                target_domain = component['value'] if component['value'] else domain
                component["explanation"] = f"Mechanism 'mx{':' + component['value'] if component['value'] else ''}': Allows mail from servers listed as MX (mail exchangers) for '{target_domain}'."
            elif component["type"] in ["ip4", "ip6"]:
                ip_address = component["value"]
                base_explanation = f"Mechanism '{component['type']}:{ip_address}': Allows mail directly from the IP address {ip_address}."
                ptr_info = "PTR lookup failed or not found."
                try:
                    ip_to_lookup = ip_address.split('/')[0] if '/' in ip_address else ip_address
                    addr = dns.reversename.from_address(ip_to_lookup)
                    ptr_records = dns.resolver.resolve(addr, "PTR")
                    ptr_info = ", ".join([str(ptr.target).rstrip('.') for ptr in ptr_records])
                except dns.resolver.NXDOMAIN: ptr_info = "No PTR record (NXDOMAIN)"
                except dns.resolver.NoAnswer: ptr_info = "No PTR record (NoAnswer)"
                except dns.exception.Timeout: ptr_info = "PTR lookup timed out"
                except dns.exception.DNSException as e: ptr_info = f"PTR lookup DNS error: {type(e).__name__}"
                except ValueError: ptr_info = f"Invalid IP for PTR lookup"
                except Exception: ptr_info = "Error looking up PTR"
                component["ptr_record"] = ptr_info
                component["explanation"] = f"{base_explanation} (Reverse DNS: {ptr_info})"
            elif component["type"] == "exists":
                component["explanation"] = f"Mechanism 'exists:{component['value']}': Checks for the existence of an A record for '{component['value']}'. If found, mail passes."
            elif component["type"] == "redirect":
                component["explanation"] = f"Modifier 'redirect={component['value']}': The entire SPF check is delegated to the policy of '{component['value']}'. No other mechanisms or modifiers should follow a redirect."
                # Note: A full SPF validator would stop processing further mechanisms here.
            else:
                component["explanation"] = f"Unknown or unparsed mechanism: {component['raw']}"
                spf_info["warnings"].append(f"Unrecognized SPF mechanism or syntax error: {component['raw']}")

            spf_info["parsed_components"].append(component)

        if not found_all_mechanism:
            # Check if there's a redirect. If so, an 'all' mechanism might not be strictly necessary in *this* record.
            is_redirected = any(comp.get("type") == "redirect" for comp in spf_info["parsed_components"])
            if not is_redirected:
                spf_info["warnings"].append("SPF record does not have an 'all' mechanism (e.g., ~all, -all) and no 'redirect' modifier. This is often an incomplete record.")
                spf_info["recommendations"].append("Add an 'all' mechanism (e.g., '~all' or '-all') or a 'redirect' modifier to your SPF record.")

    except dns.resolver.NXDOMAIN:
        spf_info["warnings"].append(f"Domain {domain} not found (NXDOMAIN) when checking SPF.")
    except dns.resolver.NoAnswer:
        spf_info["warnings"].append(f"No TXT records found for {domain}, so no SPF record.")
        spf_info["recommendations"].append("Consider adding an SPF record to prevent email spoofing.")
    except dns.exception.Timeout:
        spf_info["warnings"].append(f"DNS query timed out for TXT records of {domain} (SPF check).")
    except Exception as e:
        spf_info["warnings"].append(f"An error occurred while fetching SPF record: {e}")
    return spf_info

def get_dmarc_record(domain):
    """
    Fetches and analyzes DMARC record for a given domain.
    """
    dmarc_info = {"record": None, "parsed": {}, "warnings": [], "recommendations": []}
    dmarc_domain = f"_dmarc.{domain}"
    try:
        txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_records_found = []
        for rdata in txt_records:
            for string in rdata.strings:
                txt_string = string.decode('utf-8')
                if txt_string.startswith("v=DMARC1"):
                    dmarc_records_found.append(txt_string)

        if not dmarc_records_found:
            dmarc_info["warnings"].append(f"No DMARC record found at {dmarc_domain}.")
            dmarc_info["recommendations"].append("Implement DMARC to protect against spoofing and phishing, starting with p=none and RUA reports.")
            return dmarc_info

        if len(dmarc_records_found) > 1:
            dmarc_info["warnings"].append(f"Multiple DMARC records found at {dmarc_domain}. Only one is allowed.")
            # Analyze the first one
            dmarc_info["record"] = dmarc_records_found[0]
        else:
            dmarc_info["record"] = dmarc_records_found[0]

        # Parse DMARC record
        tags = {}
        parts = dmarc_info["record"].split(';')
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                tags[key.strip()] = value.strip()
        dmarc_info["parsed"] = tags

        # DMARC Policy checks
        policy = tags.get('p')
        if not policy:
            dmarc_info["warnings"].append("DMARC record is missing the required 'p' (policy) tag.")
        elif policy == "none":
            dmarc_info["recommendations"].append("DMARC policy 'p=none' is for monitoring. Consider moving to 'p=quarantine' or 'p=reject' after reviewing reports.")
        elif policy == "quarantine":
            dmarc_info["recommendations"].append("DMARC policy 'p=quarantine' is good. Monitor RUA reports.")
        elif policy == "reject":
            dmarc_info["recommendations"].append("DMARC policy 'p=reject' offers the strongest protection. Monitor RUA reports.")

        # RUA/RUF checks
        if not tags.get('rua'):
            dmarc_info["warnings"].append("DMARC record is missing 'rua' tag for aggregate reports. These are highly recommended.")
            dmarc_info["recommendations"].append("Add a 'rua' tag with one or more URIs (e.g., mailto:dmarcreports@example.com) to receive DMARC aggregate reports.")

    except dns.resolver.NXDOMAIN:
        dmarc_info["warnings"].append(f"DMARC CNAME or TXT record not found for {dmarc_domain} (NXDOMAIN).")
        dmarc_info["recommendations"].append("Implement DMARC to protect against spoofing and phishing.")
    except dns.resolver.NoAnswer:
        dmarc_info["warnings"].append(f"No DMARC TXT record found at {dmarc_domain}.")
        dmarc_info["recommendations"].append("Implement DMARC to protect against spoofing and phishing.")
    except dns.exception.Timeout:
        dmarc_info["warnings"].append(f"DNS query timed out for DMARC record at {dmarc_domain}.")
    except Exception as e:
        dmarc_info["warnings"].append(f"An error occurred while fetching DMARC record: {e}")
    return dmarc_info

def get_dkim_records(domain, selectors=None):
    """
    Checks for DKIM records for given selectors.
    For common providers, it can suggest selectors.
    """
    if selectors is None:
        selectors = [] # Default to empty, might be populated based on MX provider later

    dkim_info = {"selectors_checked": [], "warnings": [], "recommendations": []}

    # Suggest common selectors based on provider (this is a heuristic)
    # This part might need to be called *after* MX provider is known, or passed in
    # For now, let's assume selectors are provided or we try some common ones.
    # Common defaults:
    default_selectors = ["selector1", "selector2", "default", "google", "k1", "k2", "dkim"]

    # If no specific selectors are given, we can't magically find them all.
    # We can just inform the user.
    if not selectors and not default_selectors: # if we decide not to use default_selectors
        dkim_info["recommendations"].append("DKIM selectors are specific to your sending services. Please provide selectors to check.")
        return dkim_info

    check_selectors = list(set(selectors + default_selectors)) # Combine and unique

    for selector in check_selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        selector_status = {"selector": selector, "record": None, "found": False, "error": None}
        try:
            txt_records = dns.resolver.resolve(dkim_domain, 'TXT')
            dkim_records_found = []
            for rdata in txt_records:
                for string in rdata.strings:
                    dkim_string = string.decode('utf-8')
                    if dkim_string.startswith("v=DKIM1"):
                        dkim_records_found.append(dkim_string)

            if dkim_records_found:
                selector_status["found"] = True
                # In theory, there should be only one DKIM record per selector.
                # Concatenate if multiple parts, but take the first full record.
                selector_status["record"] = "".join(dkim_records_found[0].split()) # Remove spaces within for easier parsing
                # Basic validation: check for p= tag
                if "p=" not in selector_status["record"]:
                    selector_status["error"] = "DKIM record found but seems invalid (missing p= tag)."
                    dkim_info["warnings"].append(f"DKIM record for {dkim_domain} might be malformed (missing p=).")

            dkim_info["selectors_checked"].append(selector_status)

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            selector_status["error"] = "No DKIM record found."
            # This is expected for selectors not in use, so not necessarily a warning for all.
            dkim_info["selectors_checked"].append(selector_status)
        except dns.exception.Timeout:
            selector_status["error"] = "DNS query timed out."
            dkim_info["warnings"].append(f"DNS query timed out for DKIM record at {dkim_domain}.")
            dkim_info["selectors_checked"].append(selector_status)
        except Exception as e:
            selector_status["error"] = f"An error occurred: {e}"
            dkim_info["warnings"].append(f"An error occurred for DKIM {dkim_domain}: {e}")
            dkim_info["selectors_checked"].append(selector_status)

    found_valid_dkim = any(s['found'] and not s['error'] for s in dkim_info["selectors_checked"] if s['record'])
    if not found_valid_dkim and selectors: # If specific selectors were given and none found/valid
        dkim_info["warnings"].append(f"None of the specified DKIM selectors ({', '.join(selectors)}) were found or valid.")
    elif not found_valid_dkim:
         dkim_info["recommendations"].append(
             "No common DKIM records (e.g., selector1, google) found or valid. "
             "Ensure DKIM is configured for all sending services. "
             "You may need to specify selectors used by your domain."
        )


    return dkim_info

# Helper function to determine if any valid DKIM was found (used by health summary)
def _has_valid_dkim(dkim_info):
    if dkim_info.get("selectors_checked"):
        for item in dkim_info["selectors_checked"]:
            if item.get("found") and not item.get("error"):
                # Check for presence of p= tag as a basic validity check
                if item.get("record") and "p=" in item["record"]:
                    return True
    return False

def calculate_health_summary(domain, mx_info, spf_info, dmarc_info, dkim_info):
    """
    Calculates the overall health summary based on the gathered information.
    Returns a dictionary with status, score, and detailed findings.
    """
    summary = {"status": "", "score": 0, "details": [], "issues_count": 0}
    health_score = 0
    issues = 0

    if mx_info["records"] and not mx_info["warnings"]:
        health_score += 1
    else:
        issues +=1

    spf_all_qualifier_is_strong = False
    if spf_info["record"]:
        for component in spf_info.get("parsed_components", []):
            if component.get("type") == "all":
                if component.get("qualifier") in ["-", "~"]:
                    spf_all_qualifier_is_strong = True
                break

    if spf_info["record"] and not spf_info["warnings"] and spf_all_qualifier_is_strong:
        health_score += 1
    elif not spf_info["record"] or spf_info["warnings"]:
        issues += 1

    if dmarc_info["record"] and not dmarc_info["warnings"] and dmarc_info["parsed"].get("p") in ["quarantine", "reject"]:
        health_score += 1
    elif dmarc_info["record"] and not dmarc_info["warnings"] and dmarc_info["parsed"].get("p") == "none":
        if dmarc_info["parsed"].get("rua"):
            health_score += 0.5
        else:
            issues +=1
    elif not dmarc_info["record"] or dmarc_info["warnings"]:
        issues +=1

    has_valid_dkim_found = _has_valid_dkim(dkim_info)
    if has_valid_dkim_found:
        health_score +=1
    else:
        # Don't harshly penalize if common selectors aren't there without user input,
        # but it's an area for improvement if no DKIM is found at all.
        # If specific selectors were provided by user and none found/valid, that's an issue.
        user_provided_selectors = any(sel["user_provided"] for sel in dkim_info.get("selectors_checked", []) if "user_provided" in sel) # Requires minor change in get_dkim_records

        # For simplicity, let's assume dkim_info["warnings"] would catch specific selector failures.
        # If no DKIM whatsoever, and no specific selectors asked for, it's a soft issue.
        # This part of scoring might need more nuance if user_provided flags are not added to dkim_info
        pass


    summary["score"] = health_score
    summary["issues_count"] = issues

    if issues == 0 and health_score >= 3.5: # Allow for DKIM to be more flexible
        summary["status"] = "GOOD"
        summary["details"].append("Key email authentication records appear to be in place and configured well.")
    elif health_score >= 2:
        summary["status"] = "FAIR"
        summary["details"].append("Some configurations are good, but there are areas for improvement or warnings.")
    else:
        summary["status"] = "NEEDS ATTENTION"
        summary["details"].append("Significant issues or missing records found.")

    if not mx_info["records"]:
        summary["details"].append("- Critical: No MX records found or error fetching them. Mail delivery will fail.")
    if not spf_info["record"]:
        summary["details"].append("- Important: SPF record is missing. Higher risk of email spoofing.")
    if not dmarc_info["record"]:
        summary["details"].append("- Important: DMARC record is missing. Less protection against spoofing and phishing.")

    dkim_recommendation_needed = True
    if has_valid_dkim_found:
        dkim_recommendation_needed = False

    # Check if DKIM specific recommendations already exist. If so, don't add a generic one.
    if dkim_info.get("recommendations"):
        dkim_recommendation_needed = False

    if dkim_recommendation_needed:
         summary["details"].append("- Recommendation: Consider configuring DKIM for sending services to improve deliverability and trust.")

    return summary

def print_report_text(domain, mx_info, spf_info, dmarc_info, dkim_info, health_summary_data):
    """
    Prints a formatted text report of the email health analysis.
    """
    print(f"\n--- Email Health Report for: {domain} ---\n")

    # --- MX Records ---
    print("== MX Records ==")
    if mx_info["records"]:
        print(f"  Provider detected: {mx_info['provider']}")
        for record in mx_info["records"]:
            print(f"  - Preference: {record['preference']}, Exchange: {record['exchange']}")
    else:
        print("  No MX records found or error fetching them.")
    for warning in mx_info["warnings"]:
        print(f"  [MX WARNING] {warning}")
    print("-" * 20)

    # --- SPF Record ---

    print("\n== SPF Record ==")
    if spf_info["record"]:
        print(f"  Raw SPF Record: {spf_info['record']}\n")
        print("  Parsed SPF Components and Explanations:")
        for component in spf_info.get("parsed_components", []):
            # The explanation is now pre-formatted in get_spf_record
            # We just need to display the raw part and its generated explanation.
            raw_display = component.get('raw', 'N/A')
            explanation_display = component.get('explanation', 'No explanation available.')

            print(f"    - {raw_display:<30} : {explanation_display}")

    else:
        # This case is usually covered by warnings if a lookup failed (NXDOMAIN, NoAnswer)
        # If record is None but no warnings, it implies no TXT records were SPF-like.
        if not spf_info["warnings"]: # Only print this if no other DNS error was already reported as a warning
             print("  No SPF record found for the domain.")


    for warning in spf_info["warnings"]:
        print(f"  [SPF WARNING] {warning}")
    for rec in spf_info["recommendations"]:
        print(f"  [SPF RECOMMENDATION] {rec}")
    print("-" * 20)

    # --- DMARC Record ---
    print("\n== DMARC Record ==")
    if dmarc_info["record"]:
        print(f"  Raw DMARC Record: {dmarc_info['record']}")
        print("  Parsed DMARC Tags:")
        for key, value in dmarc_info["parsed"].items():
            print(f"    - {key}: {value}")
        policy = dmarc_info["parsed"].get('p', 'Not set')
        if policy == "none":
            print(f"  Policy (p): {policy} - Monitoring mode. Consider 'quarantine' or 'reject' after review.")
        elif policy in ["quarantine", "reject"]:
            print(f"  Policy (p): {policy} - Good, offers protection.")
        else:
            print(f"  Policy (p): {policy}")

    for warning in dmarc_info["warnings"]:
        print(f"  [DMARC WARNING] {warning}")
    for rec in dmarc_info["recommendations"]:
        print(f"  [DMARC RECOMMENDATION] {rec}")
    print("-" * 20)

    # --- DKIM Records ---
    print("\n== DKIM Records (Common Selectors) ==")
    checked_any_dkim = False
    found_valid_dkim = False
    if dkim_info["selectors_checked"]:
        for item in dkim_info["selectors_checked"]:
            checked_any_dkim = True
            if item["found"]:
                print(f"  Selector: {item['selector']}._domainkey.{domain}")
                print(f"    Status: FOUND")
                print(f"    Record: {item['record'][:60]}..." if item['record'] and len(item['record']) > 60 else item.get('record', 'N/A'))
                if item['error']:
                     print(f"    Error: {item['error']}")
                else:
                    found_valid_dkim = True # At least one valid DKIM found
            # Optionally, only print selectors that were found or had errors
            # elif item['error'] and "DNS query timed out" not in item['error']: # Don't clutter with non-existent common ones
            #     print(f"  Selector: {item['selector']}._domainkey.{domain}")
            #     print(f"    Status: Error/Not Found - {item['error']}")


    if not checked_any_dkim:
        print("  No DKIM selectors were checked.")
    elif not found_valid_dkim:
        print("  No valid DKIM records found for the common selectors checked.")

    for warning in dkim_info["warnings"]:
        print(f"  [DKIM WARNING] {warning}")
    for rec in dkim_info["recommendations"]:
        print(f"  [DKIM RECOMMENDATION] {rec}")
    print("-" * 20)

    # --- Overall Health Summary (from pre-calculated data) ---
    print("\n== Overall Health Summary ==")
    print(f"  Status: {health_summary_data['status']}")
    if health_summary_data.get("score") is not None: # Optional: print score if desired
        print(f"  Overall Score: {health_summary_data['score']:.1f} (out of 4.0 possible for MX,SPF,DMARC,DKIM)")
        print(f"  Identified Issues: {health_summary_data['issues_count']}")


    for detail in health_summary_data["details"]:
        print(f"  {detail}")

    # Add any specific recommendations from individual checks that might not be in health_summary_data details yet
    # For example, if DKIM had specific recommendations beyond the generic one.
    # This can be refined further. For now, health_summary_data aims to consolidate.

    print("\n--- End of Report ---\n")

# --- JSON Report Function ---
def print_report_json(domain, mx_info, spf_info, dmarc_info, dkim_info, health_summary_data):
    """
    Prints a JSON formatted report.
    """
    report_data = {
        "domain": domain,
        "mx_records": mx_info,
        "spf_record": spf_info,
        "dmarc_record": dmarc_info,
        "dkim_records": dkim_info,
        "health_summary": health_summary_data
    }
    print(json.dumps(report_data, indent=2))

# --- HTML Report Function ---
def print_report_html(domain, mx_info, spf_info, dmarc_info, dkim_info, health_summary_data):
    """
    Prints an HTML formatted report.
    """
    # Helper for escaping HTML
    def H(text):
        return html.escape(str(text) if text is not None else "")

    mx_warnings = "".join(f"<p class='warning'>[MX WARNING] {H(w)}</p>" for w in mx_info['warnings'])
    if mx_info['records']:
        mx_rows = "".join(
            f"<tr><td>{H(r['preference'])}</td><td>{H(r['exchange'])}</td></tr>" for r in mx_info['records']
        )
        mx_table = f"<table><tr><th>Preference</th><th>Exchange</th></tr>{mx_rows}</table>"
    else:
        mx_table = "<p>No MX records found or error fetching them.</p>"

    spf_warnings = "".join(f"<p class='warning'>[SPF WARNING] {H(w)}</p>" for w in spf_info['warnings'])
    spf_recs = "".join(f"<p class='recommendation'>[SPF RECOMMENDATION] {H(r)}</p>" for r in spf_info['recommendations'])
    spf_raw = (
        f'<p><strong>Raw SPF Record:</strong></p><div class="record-raw">{H(spf_info["record"])}</div>'
        if spf_info["record"]
        else "<p>No SPF record found.</p>"
    )
    spf_components = (
        "<h3>Parsed SPF Components:</h3><ul>"
        + "".join(
            f'<li><strong>{H(c["raw"])}:</strong> {H(c["explanation"])}</li>'
            for c in spf_info.get("parsed_components", [])
        )
        + "</ul>"
        if spf_info.get("parsed_components")
        else ""
    )

    dmarc_warnings = "".join(f"<p class='warning'>[DMARC WARNING] {H(w)}</p>" for w in dmarc_info['warnings'])
    dmarc_recs = "".join(f"<p class='recommendation'>[DMARC RECOMMENDATION] {H(r)}</p>" for r in dmarc_info['recommendations'])
    dmarc_raw = (
        f'<p><strong>Raw DMARC Record:</strong></p><div class="record-raw">{H(dmarc_info["record"])}</div>'
        if dmarc_info["record"]
        else "<p>No DMARC record found.</p>"
    )
    dmarc_tags = (
        "<h3>Parsed DMARC Tags:</h3><ul>"
        + "".join(
            f'<li><strong>{H(key)}:</strong> {H(value)}</li>'
            for key, value in dmarc_info.get("parsed", {}).items()
        )
        + "</ul>"
        if dmarc_info.get("parsed")
        else ""
    )

    dkim_warnings = "".join(f"<p class='warning'>[DKIM WARNING] {H(w)}</p>" for w in dkim_info['warnings'])
    dkim_recs = "".join(f"<p class='recommendation'>[DKIM RECOMMENDATION] {H(r)}</p>" for r in dkim_info['recommendations'])
    if dkim_info.get("selectors_checked"):
        dkim_list = "".join(
            (
                f"<li><strong>Selector:</strong> {H(s['selector'])}._domainkey.{H(domain)}"
                f"<br/><strong>Status:</strong> {'FOUND' if s['found'] else 'Not Found/Error'}<br/>"
                + (
                    f"<strong>Record:</strong> <div class='record-raw'>{H(s['record'][:100] + '...' if s['record'] and len(s['record']) > 100 else s.get('record'))}</div>"
                    if s["found"]
                    else ""
                )
                + (
                    f"<span class='error'><strong>Error:</strong> {H(s['error'])}</span>" if s["error"] else ""
                )
                + "</li>"
            )
            for s in dkim_info.get("selectors_checked", [])
        )
        dkim_html = f"<ul>{dkim_list}</ul>"
    else:
        dkim_html = "<p>No DKIM selectors were checked or results to display.</p>"

    details_list = "".join(f"<li>{H(detail)}</li>" for detail in health_summary_data["details"])

    html_output = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Health Report for {H(domain)}</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; line-height: 1.6; }}
        h1, h2, h3 {{ color: #333; }}
        h2 {{ border-bottom: 1px solid #eee; padding-bottom: 5px; }}
        .report-section {{ margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9; }}
        .record-raw {{ background-color: #eee; padding: 10px; border-radius: 3px; white-space: pre-wrap; word-wrap: break-word; font-family: monospace; }}
        .warning {{ color: orange; font-weight: bold; }}
        .recommendation {{ color: #007bff; }}
        .error {{ color: red; font-weight: bold; }}
        ul {{ list-style-type: disc; margin-left: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ text-align: left; padding: 8px; border: 1px solid #ddd; }}
        th {{ background-color: #f0f0f0; }}
        .status-GOOD {{ color: green; font-weight: bold; }}
        .status-FAIR {{ color: orange; font-weight: bold; }}
        .status-NEEDS-ATTENTION {{ color: red; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>Email Health Report for {H(domain)}</h1>

    <!-- MX Records -->
    <div class="report-section">
        <h2>MX Records</h2>
        <p><strong>Provider Detected:</strong> {H(mx_info['provider'])}</p>
        {mx_warnings}
        {mx_table}
    </div>

    <!-- SPF Record -->
    <div class="report-section">
        <h2>SPF Record</h2>
        {spf_warnings}
        {spf_recs}
        {spf_raw}
        {spf_components}
    </div>

    <!-- DMARC Record -->
    <div class="report-section">
        <h2>DMARC Record</h2>
        {dmarc_warnings}
        {dmarc_recs}
        {dmarc_raw}
        {dmarc_tags}
    </div>

    <!-- DKIM Records -->
    <div class="report-section">
        <h2>DKIM Records (Common Selectors Checked)</h2>
        {dkim_warnings}
        {dkim_recs}
        {dkim_html}
    </div>

    <!-- Overall Health Summary -->
    <div class="report-section">
        <h2>Overall Health Summary</h2>
        <p><strong>Status:</strong> <span class="status-{H(health_summary_data['status'].replace(' ', '-'))}">{H(health_summary_data['status'])}</span></p>
        <p><strong>Overall Score:</strong> {H(f"{health_summary_data['score']:.1f}")} (out of 4.0 possible)</p>
        <p><strong>Identified Issues Count:</strong> {H(health_summary_data['issues_count'])}</p>
        <h3>Details:</h3>
        <ul>{details_list}</ul>
    </div>
</body>
</html>"""
    print(html_output)


def main():
    parser = argparse.ArgumentParser(description="Analyze domain email health (MX, SPF, DMARC, DKIM).")
    parser.add_argument("domain", help="The domain to analyze (e.g., example.com).")
    parser.add_argument("--dkim-selectors", nargs='+', help="Optional: Specific DKIM selectors to check (e.g., s1 s2 google).")
    parser.add_argument("--format", choices=["text", "json", "html"], default="text", help="Output format (default: text).")

    args = parser.parse_args()
    domain = args.domain

    #print(f"Analyzing {domain}...\n")

    mx_info = get_mx_records(domain)
    spf_info = get_spf_record(domain)
    dmarc_info = get_dmarc_record(domain)

    # Pass user-specified DKIM selectors if provided
    dkim_selectors_to_check = args.dkim_selectors if args.dkim_selectors else []

    # Potentially add provider-specific selectors if known from MX
    # For example:
    # if mx_info["provider"] == "Google Workspace" and "google" not in dkim_selectors_to_check:
    #     dkim_selectors_to_check.append("google")
    # elif mx_info["provider"] == "Microsoft 365" and not any(s in dkim_selectors_to_check for s in ["selector1", "selector2"]):
    #     dkim_selectors_to_check.extend(["selector1", "selector2"])
    # We will use a default list in get_dkim_records for now, plus any user-provided ones.

    dkim_info = get_dkim_records(domain, selectors=dkim_selectors_to_check)

    # Calculate health summary data before calling format-specific report functions
    health_summary_data = calculate_health_summary(domain, mx_info, spf_info, dmarc_info, dkim_info)

    if args.format == "json":
        print_report_json(domain, mx_info, spf_info, dmarc_info, dkim_info, health_summary_data)
    elif args.format == "html":
        print_report_html(domain, mx_info, spf_info, dmarc_info, dkim_info, health_summary_data)
    else: # Default to text
        print_report_text(domain, mx_info, spf_info, dmarc_info, dkim_info, health_summary_data)

if __name__ == "__main__":
    main()
