███████╗██╗   ██╗██████╗       ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗
██╔════╝██║   ██║██╔══██╗     ██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
███████╗██║   ██║██████╔╝     ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
╚════██║██║   ██║██╔══██╗     ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
███████║╚██████╔╝██████╔╝     ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
╚══════╝ ╚═════╝ ╚═════╝       ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝

                 [ By Sylar ]
         🔍 Subdomain Reconnaissance Tool 🎯
============================================================================================
A fast, flexible subdomain enumeration tool

Usage: subd_crawler [OPTIONS] <DOMAIN>

Arguments:
  <DOMAIN>  Target domain to scan

Options:
  -w, --wordlist <WORDLIST>
          Wordlist type to use [default: light] [possible values: light, top5000, top20000, top110000, custom]
      --seclists-path <SECLISTS_PATH>
          Custom path to SecLists wordlist directory [env: SECLISTS_PATH=]
  -c, --custom-wordlist <CUSTOM_WORDLIST>
          Path to custom wordlist file (used only when wordlist type is Custom)
  -t, --threads <THREADS>
          Number of threads to use [default: 10]
  -h, --help
          Print help (see more with '--help')
  -V, --version
          Print version

