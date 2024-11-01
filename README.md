# Under the dome: Automatic Vulnerability Monitoring Generation against 1-day Attacks with AEGIS



1-day vulnerabilities are a serious security threat in open-source software (OSS), as they can be exploited by malicious actors before necessary patches are developed and deployed. This issue is particularly concerning given the widespread reliance on OSS in modern software development, especially when vulnerabilities in foundational software can affect numerous applications. Effectively monitoring 1-day vulnerability attacks is a practical solution given these concerns.



This paper presents \texttt{AEGIS}, an innovative method designed to automate the generation of eBPF monitoring for 1-day attacks. Our work begins with a study of 79 real-world vulnerabilities, then develops tailored eBPF monitoring for 71 vulnerabilities and summarizes monitoring patterns.
\texttt{AEGIS} uses three LLM agents and eBPF compiler that collaborate to generate corresponding specific monitoring strategies based on monitoring patterns from the study, produce the eBPF code, and address issues within the code, thereby automating the generation of eBPF monitoring programs.
Our evaluation demonstrated that \texttt{AEGIS} achieves an 78.13\% detection rate and 92\% precision when monitoring real-world 1-day vulnerabilities, and another experiment indicated that the eBPF monitoring programs it generates have low performance overhead. Furthermore, an ablation study highlighted the critical importance of its key components.







## Content



```
├── aegis_check.py
├── aegis_config.py
├── aegis_core.py
├── aegis_prompt_helper.py
├── aegis_retrieval.py
├── aegis_rpc.py
├── bpftrace.adoc
├── check_affected.py
├── env.yml
├── getcve.py
├── probes.pickle
├── prompts.toml
├── README.md
├── retrieval-engine
│   ├── finddefine.py
│   ├── findfunc.py
│   ├── findstruct.py
│   ├── Readme.md
│   └── test.sh
├── rq1
│   ├── bpf
│   ├── cvesw-sheet.csv
│   ├── databsae.sh
│   ├── jsons
│   ├── rq1.xlsx
│   └── webserver.sh
├── rq2
│   ├── get_all_records-pts.py
│   ├── get_single_record-pts.py
│   ├── run1by1-pts.sh
│   ├── runall-pts.sh
│   ├── run-pts.sh
│   └── suite-definition.xml
├── rq3
│   ├── jsons
│   └── rq3.xlsx
├── settings.toml
└── study
    ├── jsons
    └── study.xlsx
```





First, download and unzip the Linux Kernel Source Code and place it in the designated folder. The path should be referenced from `kernel-folder` in `aegis_config.py`.



Next, configure the Python dependency environment according to the instructions in `env.yml`. This tool uses Miniconda as the package management software.



Then, run `aegis_rpc.py` in the background to provide related services for aegis.

Additionally, please configure `API_BASE` and `API_KEY` as needed. Also, run `base64 -d prompts.toml.base64 > prompts.toml`.



`aegis_core.py` is the core of the generation process, and running it will generate the eBPF monitoring program code.



