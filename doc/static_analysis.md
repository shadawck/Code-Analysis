# Static Code Analysis 

- [Graudit](https://github.com/wireghoul/graudit/) : Grep rough audit - source code auditing tool
    ```bash
    git clone https://github.com/wireghoul/graudit/ && cd graudit
    ./graudit <source_code_path>
    ```

- [Mosca](https://github.com/CoolerVoid/Mosca) : Mosca – Manual Static Analysis Tool To Find Bugs
    ```
    git clone https://github.com/CoolerVoid/Mosca 
    make 
    ./mosca --egg eggs/<egg_module> --path <source_code_path> --ext <file_pattern> --log report.xml

- RATS : The Rough Auditing Tool for Security is an open source tool developed by Secure Software Engineers. Since then it has been acquired by Fortify, which continues to distribute it free of charge. It scans various languages, including C, C++, Perl, PHP and Python.
    ```bash
    wget http://downloads.sourceforge.net/project/expat/expat/2.0.1/expat-2.0.1.tar.gz && \
    tar -xvf expat-2.0.1.tar.gz && \
    cd expat-2.0.1 && \
    ./configure && make && make install && \
    rm expat-2.0.1.tar.gz && \ 
    cd .. && \ 
    wget https://storage.googleapis.com/google-code-archive-downloads/v2/code.google.com/rough-auditing-tool-for-security/rats-2.4.tgz && \
    tar -xzvf rats-2.4.tgz && \
    cd rats-2.4 && \
    ./configure && make && sudo make install && \ 
    rm rats-2.4.tgz && \
    cd ..
    ```

    ```bash 
    rats --quiet --xml -w 3 <path_to_source_directory>
    ```

- [FlawFinder](https://dwheeler.com/flawfinder/) : a simple program that examines C/C++ source code and reports possible security weaknesses (“flaws”) sorted by risk level. It’s very useful for quickly finding and removing at least some potential security problems before a program is widely released to the public 
    ```bash
    sudo apt install python python-pip
    pip install flawfinder
    ```

- [Infer](https://github.com/facebook/infer) : A static analyzer for Java, C, C++, and Objective-C



- [Coccinelle](https://github.com/coccinelle/coccinelle) : Coccinelle is a program matching and transformation engine which provides the language SmPL (Semantic Patch Language) for specifying desired matches and transformations in C code. 





- []() : 
- []() : 
- []() : 
- []() : 
- []() : 
- []() : 
- []() : 
- []() : 
- []() : 
- []() : 
- []() : 
- []() : 
- []() : 
- []() : 
- []() : 



### Criteria 

- Must support your programming language, but not usually a key factor once it does.
- Types of vulnerabilities it can detect (out of the OWASP Top Ten?) (plus more?)
- How accurate is it? False Positive/False Negative rates?
- Does the tool have an OWASP Benchmark score?
- Does it understand the libraries/frameworks you use?
- Does it require a fully buildable set of source?
- Can it run against binaries instead of source?
- Can it be integrated into the developer's IDE?
- How hard is it to setup/use?
- Can it be run continuously and automatically?
- License cost for the tool. (Some are sold per user, per org, per app, per line of code analyzed. Consulting licenses are frequently different than end user licenses.)