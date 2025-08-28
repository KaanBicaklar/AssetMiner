#!/bin/bash


set -e

declare -r MAX_TIMEOUT=36000 
declare -r MAX_RETRIES=3
declare -r SLEEP_INTERVAL=10

parse_arguments() {
    SINGLE_DOMAIN=""
    DOMAIN_LIST=""
    PROXY=""
    DO_SUBDOMAIN=true
    DO_HTTP=true
    DO_WAYBACK=true
    DO_CRAWL=true
    DO_DIRB=true
    DO_GF=true
    DO_NUCLEI=true
    DO_BURP=false

    FORCE_RESCAN=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -d)
                if [[ -n "$2" ]]; then
                    SINGLE_DOMAIN="$2"
                    shift 2
                else
                    echo "Error: -d requires a domain argument"
                    exit 1
                fi
                ;;
            -l)
                if [[ -n "$2" ]]; then
                    DOMAIN_LIST="$2"
                    shift 2
                else
                    echo "Error: -l requires a file argument"
                    exit 1
                fi
                ;;
            --skip-subdomain)
                DO_SUBDOMAIN=false
                shift
                ;;
            --skip-http)
                DO_HTTP=false
                shift
                ;;
            --skip-wayback)
                DO_WAYBACK=false
                shift
                ;;
            --skip-crawl)
                DO_CRAWL=false
                shift
                ;;
            --skip-dirb)
                DO_DIRB=false
                shift
                ;;
            --skip-gf)
                DO_GF=false
                shift
                ;;
            --skip-nuclei)
                DO_NUCLEI=false
                shift
                ;;
            --with-burp)
                DO_BURP=true
                shift
                ;;

            --force-rescan)
                FORCE_RESCAN=true
                shift
                ;;
            *)
                if [[ -z "$PROXY" ]]; then
                    PROXY="$1"
                    shift
                else
                    echo "Error: Unknown argument: $1"
                    show_usage
                    exit 1
                fi
                ;;
        esac
    done

    if [[ -z "$SINGLE_DOMAIN" ]] && [[ -z "$DOMAIN_LIST" ]]; then
        echo "Error: Either -d <domain> or -l <domain_list> must be specified"
        show_usage
        exit 1
    fi

    if [[ -n "$SINGLE_DOMAIN" ]] && [[ -n "$DOMAIN_LIST" ]]; then
        echo "Error: Cannot specify both -d and -l options"
        show_usage
        exit 1
    fi        
    if [[ -z "$PROXY" ]] && [[ "$DO_BURP" = true ]]; then
        echo "Error: Proxy argument is required when Burp integration is enabled"
        show_usage
        exit 1
    fi

    if [[ -n "$PROXY" ]]; then
        if ! echo "$PROXY" | grep -qP '^http(s)?://[a-zA-Z0-9.-]+:[0-9]+$'; then
            echo "Error: Invalid proxy format. Should be http(s)://host:port"
            exit 1
        fi
    fi



    if [[ -n "$DOMAIN_LIST" ]] && [[ ! -f "$DOMAIN_LIST" ]]; then
        echo "Error: Domain list file not found: $DOMAIN_LIST"
        exit 1
    fi

    export SINGLE_DOMAIN DOMAIN_LIST PROXY DO_SUBDOMAIN DO_HTTP DO_WAYBACK DO_CRAWL DO_DIRB DO_GF DO_NUCLEI DO_BURP  FORCE_RESCAN
}

show_usage() {
    cat << EOF


 ▄▄▄        ██████   ██████ ▓█████▄▄▄█████▓ ███▄ ▄███▓ ██▓ ███▄    █ ▓█████  ██▀███  
▒████▄    ▒██    ▒ ▒██    ▒ ▓█   ▀▓  ██▒ ▓▒▓██▒▀█▀ ██▒▓██▒ ██ ▀█   █ ▓█   ▀ ▓██ ▒ ██▒
▒██  ▀█▄  ░ ▓██▄   ░ ▓██▄   ▒███  ▒ ▓██░ ▒░▓██    ▓██░▒██▒▓██  ▀█ ██▒▒███   ▓██ ░▄█ ▒
░██▄▄▄▄██   ▒   ██▒  ▒   ██▒▒▓█  ▄░ ▓██▓ ░ ▒██    ▒██ ░██░▓██▒  ▐▌██▒▒▓█  ▄ ▒██▀▀█▄  
 ▓█   ▓██▒▒██████▒▒▒██████▒▒░▒████▒ ▒██▒ ░ ▒██▒   ░██▒░██░▒██░   ▓██░░▒████▒░██▓ ▒██▒
 ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░░ ▒░ ░ ▒ ░░   ░ ▒░   ░  ░░▓  ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░
  ▒   ▒▒ ░░ ░▒  ░ ░░ ░▒  ░ ░ ░ ░  ░   ░    ░  ░      ░ ▒ ░░ ░░   ░ ▒░ ░ ░  ░  ░▒ ░ ▒░
  ░   ▒   ░  ░  ░  ░  ░  ░     ░    ░      ░      ░    ▒ ░   ░   ░ ░    ░     ░░   ░ 
      ░  ░      ░        ░     ░  ░               ░    ░           ░    ░  ░   ░     
Usage: $0 [options] (-d <domain> | -l <domain_list>) <proxy>

Required arguments:
  -d <domain>           Single domain to scan
  -l <domain_list>      File containing list of domains (one per line)
  <proxy>               Burp Suite proxy URL (http://host:port)

Options:
  -h, --help           Show this help message
  --skip-subdomain     Skip subdomain enumeration phase
  --skip-http          Skip HTTP probe phase
  --skip-wayback       Skip wayback URL collection
  --skip-crawl         Skip crawling with katana
  --skip-dirb          Skip directory bruteforcing with Gobuster
  --skip-gf            Skip pattern matching with gf
  --skip-nuclei        Skip nuclei scanning
  --with-burp          Send trafic to  Burp Suite

  --force-rescan       Force rescan, ignore existing results

Examples:
  Single domain:     $0 -d example.com 
  Multiple domains:  $0 -l domains.txt
  With options:      $0 -l domains.txt http://burp:8080 --with-burp  --force-rescan     
EOF
}

cleanup() {
    local output_dir="$1"
    echo "[*] Performing cleanup..."
    
    rm -f "${output_dir}/gobuster_temp_"* 2>/dev/null || true
    rm -f "${output_dir}/katana_temp_"* 2>/dev/null || true
    rm -f "${output_dir}/tmp_"* 2>/dev/null || true
    rm -f "${output_dir}/*.lock" 2>/dev/null || true
    rm -f "${output_dir}/subdomains1" 2>/dev/null || true
    
    echo "[*] Cleanup completed"
}

check_lock() {
    local lock_file="$1"
    local max_age=${2:-$MAX_TIMEOUT}
    
    if [ -f "$lock_file" ]; then
        local lock_time=$(stat -c %Y "$lock_file" 2>/dev/null || echo 0)
        local current_time=$(date +%s)
        local age=$((current_time - lock_time))
        
        if [ $age -gt $max_age ]; then
            echo "[!] Stale lock found, removing: $lock_file"
            rm -f "$lock_file"
            return 1
        fi
        return 0
    fi
    return 1
}

create_lock() {
    local lock_file="$1"
    echo "[*] Creating lock: $lock_file"
    touch "$lock_file"
}

remove_lock() {
    local lock_file="$1"
    echo "[*] Removing lock: $lock_file"
    rm -f "$lock_file"
}

check_resume() {
    local output_file="$1"
    local min_size="$2"  # Minimum dosya boyutu (byte)
    local force_rescan="${3:-false}"  # Zorla yeniden tarama
    
    if [ "$force_rescan" = "true" ]; then
        echo "[*] Force rescan enabled, ignoring existing results"
        return 1
    fi
    
    if [ -f "$output_file" ]; then
        local file_size=$(stat -f%z "$output_file" 2>/dev/null || stat -c%s "$output_file" 2>/dev/null)
        if [ -n "$file_size" ] && [ "$file_size" -gt "$min_size" ]; then
            echo "[*] Found existing results in $output_file (size: $file_size bytes)"
            return 0
        else
            echo "[*] Found incomplete or empty results in $output_file"
            return 1
        fi
    fi
    return 1
}

do_subdomain_enum() {
    local domain="$1"
    local output_dir="$2"
    local force_rescan="${3:-false}"
    local lock_file="${output_dir}/subdomain.lock"
    local final_output="${output_dir}/subdomains"
    local retry_count=0
    
    # Resume kontrolü
    if check_resume "$final_output" 100 "$force_rescan"; then
        echo "[+] Using existing subdomain results from $final_output"
        return 0
    fi
    
    if check_lock "$lock_file"; then
        echo "[*] Subdomain enumeration already in progress"
        return 0
    fi
    
    create_lock "$lock_file"
    
    echo "[+] Starting subdomain enumeration for $domain..."
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        {
            subfinder -d "$domain" -rL dns-resolvers.txt -recursive -o "${output_dir}/subdomains_subfinder" 
            echo "subfinder completed"
            sleep 10 #
            assetfinder --subs-only "$domain" > "${output_dir}/subdomains_assetfinder" 
            echo "assetfinder completed"
             sleep 10 #
            shuffledns -d "$domain" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt  -r dns-resolvers.txt > "${output_dir}/subdomains_shuffledns" 
            echo "subfinder, assetfinder, shuffledns completed"
            echo "sleeping 2 minutes"
            sleep 120 # 2 dakika bekle
            # Sonuçları birleştir ve temizle
            cat "${output_dir}/subdomains_"* 2>/dev/null | sort -u > "${output_dir}/subdomains"
            echo "subdomains file created"
            
            if [ -s "${output_dir}/subdomains" ]; then
                echo "[+] Found $(wc -l < "${output_dir}/subdomains") unique subdomains"
                break
            else
                ((retry_count++))
                echo "[!] No subdomains found, retrying ($retry_count/$MAX_RETRIES)..."
            fi
        } || {
            echo "[-] Error in subdomain enumeration iteration $retry_count"
            ((retry_count++))
        }
    done
    
    remove_lock "$lock_file"
    
    if [ $retry_count -eq $MAX_RETRIES ]; then
        echo "[-] Subdomain enumeration failed after $MAX_RETRIES attempts"
        return 1
    fi
}

do_http_probe() {
    local output_dir="$1"
    local force_rescan="${2:-false}"
    local lock_file="${output_dir}/httpx.lock"
    local final_output="${output_dir}/httpx"
    local retry_count=0
    
    if check_resume "$final_output" 50 "$force_rescan"; then
        echo "[+] Using existing HTTP probe results from $final_output"
        return 0
    fi
    
    if ! [ -f "${output_dir}/subdomains" ]; then
        echo "[-] Subdomain file not found"
        return 1
    fi
    
    if check_lock "$lock_file"; then
        echo "[*] HTTP probing already in progress or completed"
        return 0
    fi
    
    create_lock "$lock_file"
    retry_count=0
    
    echo "[+] Starting HTTP probe..."
    local common_ports="80,81,300,443,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4443,4444,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8444,8500,8800,8834,8880,8881,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,27201,32000,55440,55672"
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        local httpx_cmd="httpx -silent -no-color -random-agent -ports \"$common_ports\" -timeout 5 -t 1 -rl 1"
        

        
        if cat "${output_dir}/subdomains" | eval "$httpx_cmd" > "${output_dir}/httpx"; then
            if [ -s "${output_dir}/httpx" ]; then
                echo "[+] Found $(wc -l < "${output_dir}/httpx") live HTTP endpoints"
                break
            fi
        fi
        
        ((retry_count++))
        echo "[!] HTTP probe failed or no results, retrying ($retry_count/$MAX_RETRIES)..."
    done
    
    remove_lock "$lock_file"
    
    if [ $retry_count -eq $MAX_RETRIES ]; then
        echo "[-] HTTP probe failed after $MAX_RETRIES attempts"
        return 1
    fi
}

do_wayback() {
    local output_dir="$1"
    local force_rescan="${2:-false}"
    local lock_file="${output_dir}/wayback.lock"
    local final_output="${output_dir}/waybacksorted"
    local retry_count=0
    
    if check_resume "$final_output" 100 "$force_rescan"; then
        echo "[+] Using existing wayback results from $final_output"
        return 0
    fi
    
    if ! [ -f "${output_dir}/subdomains" ]; then
        echo "[-] Subdomain file not found"
        return 1
    fi
    
    if check_lock "$lock_file"; then
        return 0
    fi
    
    create_lock "$lock_file"
    retry_count=0
    
    echo "[+] Starting wayback URL collection..."
    
    while [ $retry_count -lt $MAX_RETRIES ]; do
        if cat "${output_dir}/subdomains" | waybackurls > "${output_dir}/waybackdata_tmp"; then
            if [ -s "${output_dir}/waybackdata_tmp" ]; then
                sort -u "${output_dir}/waybackdata_tmp" > "${output_dir}/waybacksorted"
                echo "[+] Collected $(wc -l < "${output_dir}/waybacksorted") unique URLs from wayback"
                break
            fi
        fi
        
        ((retry_count++))
        echo "[!] Wayback collection failed or no results, retrying ($retry_count/$MAX_RETRIES)..."
    done
    
    rm -f "${output_dir}/waybackdata_tmp"
    remove_lock "$lock_file"
    
    if [ $retry_count -eq $MAX_RETRIES ]; then
        echo "[-] Wayback collection failed after $MAX_RETRIES attempts"
        return 1
    fi
}

do_gf_patterns() {
    local domain="$1"
    local output_dir="$2"
    local proxy="$3"
    local force_rescan="${4:-false}"
    local lock_file="${output_dir}/gf.lock"
    local final_output="${output_dir}/gfcikti"
    
    if check_resume "$final_output" 50 "$force_rescan"; then
        echo "[+] Using existing pattern matching results from $final_output"
        return 0
    fi
    
    if check_lock "$lock_file"; then
        return 0
    fi
    
    create_lock "$lock_file"
    echo "[+] Starting GF pattern matching..."
    
    patterns=("ssrf" "rce" "redirect" "sqli" "lfi" "ssti" "xss" "interestingEXT" "debug_logic" "idor" "interestingparams"  "interestingsubs")
    
    : >> "${output_dir}/gfcikti"

    for pattern in "${patterns[@]}"; do
        echo "[+] Scanning for $pattern in $domain..."
        if [ -f "${output_dir}/AssetListsDeduped" ]; then
          
            
            cat "${output_dir}/AssetListsDeduped" | \
                gf "$pattern" > "${output_dir}/gfcikti_$pattern" 
        fi
    done
    cat "${output_dir}/gfcikti_"* > "${output_dir}/gfcikti"
    echo "[+] Pattern matching completed"
    remove_lock "$lock_file"
}

do_nuclei_scans() {
    local domain="$1"
    local output_dir="$2"
    local force_rescan="${3:-false}"
    local lock_file="${output_dir}/nuclei.lock"
    local dast_output="${output_dir}/fuzzing_dast"
    local httpx_output="${output_dir}/nucleihttpx"
    local subs_output="${output_dir}/nucleisubs"
    
    local resume=true
    if ! check_resume "$dast_output" 50 "$force_rescan"; then
        resume=false
    fi
    if ! check_resume "$httpx_output" 50 "$force_rescan"; then
        resume=false
    fi
    if ! check_resume "$subs_output" 50 "$force_rescan"; then
        resume=false
    fi
    
    if [ "$resume" = true ]; then
        echo "[+] Using existing Nuclei scan results"
        return 0
    fi
    
    if check_lock "$lock_file"; then
        echo "[*] Nuclei scanning already in progress or completed"
        return 0
    fi
    
    create_lock "$lock_file"
    echo "[+] Starting Nuclei scans..."
    
    if [ -f "${output_dir}/gfcikti" ]; then
        echo "[+] Running Nuclei DAST scan on pattern matches..."
        nuclei -list "${output_dir}/gfcikti" \
               -dast \
               -rl 1 \
               -o "${output_dir}/fuzzing_dast" || true
    fi
    
    if [ -f "${output_dir}/httpx" ]; then
        echo "[+] Running Nuclei scan on live HTTP endpoints..."
        nuclei -l "${output_dir}/httpx" \
               -rl 1 \
               -o "${output_dir}/nucleihttpx" || true
    fi
    
    if [ -f "${output_dir}/subdomains" ]; then
        echo "[+] Running Nuclei scan on subdomains..."
        nuclei -l "${output_dir}/subdomains" \
               -rl 1 \
               -o "${output_dir}/nucleisubs" || true
    fi
    
    remove_lock "$lock_file"
    echo "[+] Nuclei scans completed"
}

do_directory_scan() {
    local output_dir="$1"
    local force_rescan="${2:-false}"
    local lock_file="${output_dir}/gobuster.lock"
    local final_output="${output_dir}/gobuster_results"
    local retry_count=0
    
    if check_resume "$final_output" 100 "$force_rescan"; then
        echo "[+] Using existing directory scan results from $final_output"
        return 0
    fi
    
    if [ ! -f "${output_dir}/httpx" ]; then
        echo "[-] HTTP endpoints file not found"
        return 1
    fi
    
    create_lock "$lock_file"
    echo "[+] Starting directory scanning with gobuster..."
    
    local temp_results="${output_dir}/gobuster_temp_results"
    : > "$temp_results"
    
    while read -r url; do
        echo "[+] Scanning directories for: $url"
        
        if ! gobuster dir \
            -u "$url" \
            -w /usr/share/wordlists/dirb/common.txt \
            -t 1 \
            -o "${output_dir}/gobuster_temp_${url//[^a-zA-Z0-9]/_}" \
            -q \
            --no-error \
            -k 2>/dev/null; then
            echo "[-] Gobuster scan failed for $url"
            continue
        fi
       
        if [ -f "${output_dir}/gobuster_temp_${url//[^a-zA-Z0-9]/_}" ]; then
             cat "${output_dir}/gobuster_temp_${url//[^a-zA-Z0-9]/_}" |  awk -v u="$url" '{print u $1}' >> "$temp_results"
            rm -f "${output_dir}/gobuster_temp_${url//[^a-zA-Z0-9]/_}"
        fi
        
    done < "${output_dir}/httpx"
    
    if [ -s "$temp_results" ]; then
        echo "[+] Directory scanning completed successfully"
        mv "$temp_results" "${output_dir}/gobuster_results"
        echo "[+] Found $(wc -l < "${output_dir}/gobuster_results") directories"
    else
        echo "[-] No directories found"
        rm -f "$temp_results"
    fi
    
    remove_lock "$lock_file"
}

do_katana_crawl() {
    local output_dir="$1"
    local proxy="$2"
    local force_rescan="${3:-false}"
    local lock_file="${output_dir}/katana.lock"
    local final_output="${output_dir}/katana_results"
    local retry_count=0
    
    if check_resume "$final_output" 100 "$force_rescan"; then
        echo "[+] Using existing Katana results from $final_output"
        return 0
    fi
    
    if [ ! -f "${output_dir}/httpx" ]; then
        echo "[-] HTTP endpoints file not found"
        return 1
    fi
    
    create_lock "$lock_file"
    echo "[+] Starting Katana crawling..."
    
    local temp_results="${output_dir}/katana_temp_results"
    : > "$temp_results"
    
    while read -r url; do
        echo "[+] Crawling: $url"
        
        local katana_cmd="katana -u $url -silent -jc -kf -aff -d 5  -rl 5 -o ${output_dir}/katana_temp_${url//[^a-zA-Z0-9]/_}"
        
        if [ "$DO_BURP" = true ] && [ -n "$proxy" ]; then
            katana_cmd="$katana_cmd -proxy $proxy"
        fi

       

        if ! eval "$katana_cmd" 2>/dev/null; then
            echo "[-] Katana crawl failed for $url"
            continue
        fi
        
        if [ -f "${output_dir}/katana_temp_${url//[^a-zA-Z0-9]/_}" ]; then
            cat "${output_dir}/katana_temp_${url//[^a-zA-Z0-9]/_}" >> "$temp_results"
            rm -f "${output_dir}/katana_temp_${url//[^a-zA-Z0-9]/_}"
        fi
        
    done < "${output_dir}/httpx"
    
    
    if [ -s "$temp_results" ]; then
        echo "[+] Crawling completed successfully"
        sort -u "$temp_results" > "${output_dir}/katana_results"
        echo "[+] Found $(wc -l < "${output_dir}/katana_results") unique URLs"
        rm -f "$temp_results"
    else
        echo "[-] No URLs found during crawling"
        rm -f "$temp_results"
    fi
    
    remove_lock "$lock_file"
}



merge_results() {
    local output_dir="$1"
    local domain="$2"
    
    echo "[+] Merging all results for $domain..."
    
    local merged_dir="${output_dir}/merged_results"
    mkdir -p "$merged_dir"
    
    {
        [ -f "${output_dir}/httpx" ] && cat "${output_dir}/httpx"
        [ -f "${output_dir}/waybacksorted" ] && cat "${output_dir}/waybacksorted"
        [ -f "${output_dir}/katana_results" ] && cat "${output_dir}/katana_results"
        [ -f "${output_dir}/gobuster_results" ] && cat "${output_dir}/gobuster_results"
    } | sort -u > "${merged_dir}/all_urls.txt"
    
    {
        [ -f "${output_dir}/nucleihttpx" ] && cat "${output_dir}/nucleihttpx"
        [ -f "${output_dir}/nucleisubs" ] && cat "${output_dir}/nucleisubs"
        [ -f "${output_dir}/fuzzing_dast" ] && cat "${output_dir}/fuzzing_dast"
        [ -f "${output_dir}/gfcikti" ] && cat "${output_dir}/gfcikti"
    } > "${merged_dir}/all_findings.txt"
    
    {
        echo "# Scan Results for $domain"
        echo "## Summary"
        echo "- Scan Date: $(date)"
        echo "- Target Domain: $domain"
        echo
        echo "## Statistics"
        [ -f "${output_dir}/subdomains" ] && echo "- Total Subdomains: $(wc -l < "${output_dir}/subdomains")"
        [ -f "${merged_dir}/all_urls.txt" ] && echo "- Total Unique URLs: $(wc -l < "${merged_dir}/all_urls.txt")"
        [ -f "${merged_dir}/all_findings.txt" ] && echo "- Total Security Findings: $(wc -l < "${merged_dir}/all_findings.txt")"
        echo
        echo "## Detailed Results"
        echo "All detailed results can be found in the following files:"
        echo "- All URLs: merged_results/all_urls.txt"

    } > "${output_dir}/SUMMARY.md"
    
    echo "[+] Results merged successfully"
    echo "[+] Summary report created at: ${output_dir}/SUMMARY.md"
}

scan_domain() {
    local domain="$1"
    local proxy="$2"
    local output_dir="${domain}.monascanner"
    
    if [ -d "$output_dir" ] && [ "$FORCE_RESCAN" = false ]; then
        echo "[*] Found existing scan directory: $output_dir"
        echo "[*] Using existing results where available (use --force-rescan to ignore)"
    fi
    
    mkdir -p "$output_dir" || { echo "Error: Could not create output directory"; return 1; }
    
    trap 'cleanup "$output_dir"' EXIT INT TERM
    
    echo "[+] Starting comprehensive scan for domain: $domain"
    echo "[+] Output directory: $output_dir"
    
    if [ "$DO_SUBDOMAIN" = true ]; then
        echo "[+] Starting subdomain enumeration..."
        if ! do_subdomain_enum "$domain" "$output_dir" "$FORCE_RESCAN"; then
            echo "[-] Subdomain enumeration failed, but continuing with available results..."
        fi
    else
        echo "[*] Skipping subdomain enumeration (--skip-subdomain specified)"
        echo "$domain" > "${output_dir}/subdomains"
    fi

    if [ "$DO_HTTP" = true ]; then
        echo "[+] Starting HTTP probe..."
        if ! do_http_probe "$output_dir" "$FORCE_RESCAN"; then
            echo "[-] HTTP probe failed, but continuing..."
        fi
    else
        echo "[*] Skipping HTTP probe (--skip-http specified)"
        cat "${output_dir}/subdomains" > "${output_dir}/httpx"
    fi

    if [ "$DO_WAYBACK" = true ]; then
        echo "[+] Starting wayback URL collection..."
        if ! do_wayback "$output_dir" "$FORCE_RESCAN"; then
            echo "[-] Wayback collection failed, but continuing..."
        fi
    else
        echo "[*] Skipping wayback collection (--skip-wayback specified)"
        cat "${output_dir}/httpx" > "${output_dir}/waybacksorted"
    fi

    if [ "$DO_DIRB" = true ]; then
        echo "[+] Starting directory scanning..."
        if ! do_directory_scan "$output_dir" "$FORCE_RESCAN"; then
            echo "[-] Directory scanning failed, but continuing..."
        fi
    else
        echo "[*] Skipping directory scanning (--skip-dirb specified)"
        cat "${output_dir}/httpx" > "${output_dir}/gobuster_results"
    fi

    if [ "$DO_CRAWL" = true ]; then
        echo "[+] Starting Katana crawling..."
        if ! do_katana_crawl "$output_dir" "$proxy" "$FORCE_RESCAN"; then
            echo "[-] Katana crawling failed, but continuing..."
        fi
    else
        echo "[*] Skipping Katana crawling (--skip-crawl specified)"
        cat "${output_dir}/httpx" > "${output_dir}/katana_results"
    fi

    [ -f "${output_dir}/waybacksorted" ] && cat "${output_dir}/waybacksorted" >> "${output_dir}/temp_urls_for_gf"
    [ -f "${output_dir}/katana_results" ] && cat "${output_dir}/katana_results" >> "${output_dir}/temp_urls_for_gf"
    [ -f "${output_dir}/gobuster_results" ] && cat "${output_dir}/gobuster_results" >> "${output_dir}/temp_urls_for_gf"
    [ -f "${output_dir}/temp_urls_for_gf" ] && cat "${output_dir}/temp_urls_for_gf" | sort -u > "${output_dir}/AssetLists"
    echo "[+] Combined URLs from wayback, katana, and gobuster into ${output_dir}/AssetLists"
    [ -f "${output_dir}/AssetLists" ] && cat "${output_dir}/AssetLists" | python3 urldeduper.py --blacklist png,pdf,jpeg,jpg,ico,tiff,woff2,woff,tff,svg,css,gif,webp > "${output_dir}/AssetListsDeduped"

    if [ "$DO_GF" = true ]; then
        echo "[+] Starting pattern matching..."
        if [ "$DO_BURP" = true ]; then
            do_gf_patterns "$domain" "$output_dir" "$proxy" "$FORCE_RESCAN"
        else
            do_gf_patterns "$domain" "$output_dir" "" "$FORCE_RESCAN"
        fi
    else
        echo "[*] Skipping pattern matching --skip-gf specified"
        cat "${output_dir}/httpx" > "${output_dir}/gfcikti"
    fi

    if [ "$DO_NUCLEI" = true ]; then
        echo "[+] Starting Nuclei scans..."
        echo "[*] Checking required files for Nuclei scans..."

        local can_run_nuclei=false

        if [ -f "${output_dir}/gfcikti" ]; then
            echo "[*] Found GF output file for DAST scan"
            can_run_nuclei=true
        fi

        if [ -f "${output_dir}/httpx" ]; then
            echo "[*] Found HTTP endpoints file"
            can_run_nuclei=true
        fi

        if [ -f "${output_dir}/subdomains" ]; then
            echo "[*] Found subdomains file"
            can_run_nuclei=true
        fi

        if [ "$can_run_nuclei" = true ]; then
            if ! do_nuclei_scans "$domain" "$output_dir" "$FORCE_RESCAN"; then
                echo "[-] Nuclei scans failed, but continuing..."
            fi
        else
            echo "[-] No input files found for Nuclei scans, skipping..."
        fi
    else
        echo "[*] Skipping Nuclei scans (--skip-nuclei specified)"
    fi
}

check_requirements() {
    echo "[*] Checking required tools..."
    
    local required_tools=(
        "subfinder"
        "assetfinder"
        "shuffledns"
        "httpx"
        "waybackurls"
        "gobuster"
        "gf"
        "qsreplace"
        "nuclei"
        "curl"
        "katana"
        "jq"
    )
    
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
            echo "[-] Missing required tool: $tool"
        else
            echo "[+] Found required tool: $tool"
        fi
    done
    
    if [ ! -f "dns-resolvers.txt" ]; then
        echo "[-] Missing dns-resolvers.txt file"
        missing_tools+=("dns-resolvers.txt")
    fi
    
    if [ ! -f "urldeduper.py" ]; then
        echo "[-] urldeduper.py file"
        missing_tools+=("urldeduper.py")
    fi
    
    if [ ! -f "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt" ]; then
        echo "[-] Missing SecLists DNS wordlist"
        missing_tools+=("seclists")
    fi

    local gf_dir="$HOME/.gf"
    if [ ! -d "$gf_dir" ] || [ -z "$(ls -A "$gf_dir"/*.json 2>/dev/null)" ]; then
        echo "[-] Missing GF patterns"
        missing_tools+=("gf-patterns")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "\n[-] Missing required tools or files. Would you like to install them? (y/n)"
        read -r user_input
        if [[ "$user_input" == "y" || "$user_input" == "Y" ]]; then
            for tool in "${missing_tools[@]}"; do
                case $tool in
                    "subfinder")
                        echo "Installing subfinder..."
                        GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
                        ;;
                    "assetfinder")
                        echo "Installing assetfinder..."
                        go install github.com/tomnomnom/assetfinder@latest
                        ;;
                    "shuffledns")
                        echo "Installing shuffledns..."
                        GO111MODULE=on go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
                        ;;
                    "httpx")
                        echo "Installing httpx..."
                        GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
                        ;;
                    "waybackurls")
                        echo "Installing waybackurls..."
                        go install github.com/tomnomnom/waybackurls@latest
                        ;;
                    "gobuster")
                        echo "Installing gobuster..."
                        go install github.com/OJ/gobuster/v3@latest
                        ;;
                    "gf")
                        echo "Installing gf..."
                        go install github.com/tomnomnom/gf@latest
                        ;;
                    "qsreplace")
                        echo "Installing qsreplace..."
                        go install github.com/tomnomnom/qsreplace@latest
                        ;;
                    "nuclei")
                        echo "Installing nuclei..."
                        GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
                        ;;
                    "katana")
                        echo "Installing katana..."
                        GO111MODULE=on go install github.com/projectdiscovery/katana/cmd/katana@latest
                        ;;
                    "dns-resolvers.txt")
                        echo "Downloading dns-resolvers.txt..."
                        wget https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O dns-resolvers.txt
                        ;;
                    "urldeduper.py")
                        echo "Downloading urldeduper.py..."
                        wget https://raw.githubusercontent.com/KaanBicaklar/urldeduper/refs/heads/main/urldeduper.py -O urldeduper.py
                        ;;
                    "seclists")
                        echo "Installing SecLists..."
                        sudo apt install seclists || git clone https://github.com/danielmiessler/SecLists.git
                        ;;
                    "jq")
                        echo "Installing jq..."
                        sudo apt install jq || brew install jq
                        ;;
                    "gf-patterns")
                        echo "Installing GF patterns..."
                        git clone https://github.com/1ndianl33t/Gf-Patterns
                        mkdir -p "$gf_dir"
                        mv Gf-Patterns/*.json "$gf_dir"
                        rm -rf Gf-Patterns
                        ;;
                esac
            done
            echo "[+] All missing tools and files have been installed!"
        else
            echo "[-] Missing tools or files were not installed. Exiting..."
            exit 1
        fi
    else
        echo "[+] All required tools are installed!"
    fi
}

validate_url() {
    local url="$1"
    if [[ "$url" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9][a-zA-Z0-9-]*)*\.[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    return 1
}

main() {
    parse_arguments "$@"
    check_requirements
    
    if [ -n "$SINGLE_DOMAIN" ]; then
        scan_domain "$SINGLE_DOMAIN" "$PROXY"
    elif [ -n "$DOMAIN_LIST" ]; then
        while IFS= read -r domain || [ -n "$domain" ]; do
            if [ -n "$domain" ] && [[ ! "$domain" =~ ^[[:space:]]*# ]]; then
                domain=$(echo "$domain" | tr -d '[:space:]')
                if validate_url "$domain"; then
                    scan_domain "$domain" "$PROXY"
                else
                    echo "[-] Invalid domain format, skipping: $domain"
                fi
            fi
        done < "$DOMAIN_LIST"
    
    fi
    echo "[+] All scanning operations completed successfully!"
}

main "$@"
