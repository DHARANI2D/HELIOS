import requests
import json

def test_analysis():
    url = "http://127.0.0.1:8000/api/analyze/email"
    file_path = "samples/whitelist_test.eml"
    
    # Create a dummy EML if it doesn't exist or use existing
    # We'll assume the existence of samples/malicious.eml from context
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f, 'message/rfc822')}
            response = requests.post(url, files=files)
            
        if response.status_code == 200:
            data = response.json()
            print("✓ API Request Successful")
            print(f"Total Score: {data.get('total_score')}")
            print(f"Verdict: {data.get('verdict')}")
            
            print("\n--- New Features Check ---")
            
            # Check Extracted URLs
            urls = data.get('extracted_urls', [])
            print(f"✓ Extracted URLs: {len(urls)} found")
            for u in urls[:3]: print(f"  - {u}")
            
            # Check Attachments
            atts = data.get('attachments', [])
            print(f"✓ Attachments: {len(atts)} found")
            for a in atts:
                print(f"  - {a.get('filename')} (Risk: {a.get('risk')})")
                
            # Check Header Reasons (MX)
            h_reasons = data.get('header_reasons', [])
            print(f"✓ Header Reasons: {len(h_reasons)}")
            for r in h_reasons: print(f"  - {r}")

            # Check Body Reasons (TOAD)
            b_reasons = data.get('body_reasons', [])
            print(f"✓ Body Reasons: {len(b_reasons)}")
            for r in b_reasons: print(f"  - {r}")

            # Check MxToolbox
            mx = data.get('mxtoolbox_analysis', {})
            if mx:
                # Detailed Details Check
                monitors = ['mx', 'blacklist', 'spf', 'dmarc', 'dkim', 'dns', 'smtp']
                for m in monitors:
                    data_m = mx.get(m, {})
                    passed = data_m.get('passed')
                    details = data_m.get('details', [])
                    print(f"  - {m.upper()} Passed: {passed} (Details: {len(details)})")
                    if details and len(details) > 0:
                        first = details[0]
                        print(f"    Sample: [{first.get('status')}] {first.get('name')}: {first.get('info')[:50]}...")

                if mx.get('dkim', {}).get('checked'):
                     print(f"  - DKIM Passed: {mx.get('dkim', {}).get('passed')}")
            else:
                print("⚠ MxToolbox Analysis Missing (Expected if no API Key)")

            # Check Attachments Details
            if data.get('attachments'):
                print(f"✓ Attachments Found: {len(data['attachments'])}")
                for att in data['attachments']:
                    vt = att.get('vt_stats') or "N/A"
                    sig = att.get('signature')
                    sig_str = f"Signed by {sig['product']}" if sig else "Unsigned"
                    print(f"  - {att['filename']} (VT: {vt}) [{sig_str}]")

            # Check Header Visualization
            print(f"✓ Header Analysis:")
            hops = data.get('hops', [])
            print(f"  - Hops Found: {len(hops)}")
            auth = data.get('auth_results', {})
            print(f"  - Auth Results: SPF={auth.get('spf', {}).get('status')}, DKIM={auth.get('dkim', {}).get('status')}, DMARC={auth.get('dmarc', {}).get('status')}")
            raw = data.get('all_headers', [])
            print(f"  - Raw Headers Extracted: {len(raw)}")

            # Check Whitelist
            wl = data.get('whitelisted_domains', [])
            print(f"✓ Whitelisted Domains: {len(wl)}")
            for w in wl: print(f"  - {w}")

        else:
            print(f"✗ API Request Failed: {response.status_code}")
            print(response.text)
            
    except Exception as e:
        print(f"✗ Test Failed: {e}")

if __name__ == "__main__":
    test_analysis()
