# LiteAudit

LiteAudit is a file-verification application that runs on your local computer.


#### 1) PROBLEM:
Businesses and academic departments frequently ingest uploaded documents (PDFs, text files, etc.) for their daily operations. While there are antivirus software currently available, LiteAudit differs by being an application that has the ability to detect the structural anomalies of different documents. These problems can be: problematic SQL injections, script file renames, etc. Any individual, team or business that handles digital forms regularly can be at risk of allowing suspicious files to access their digital environment. Ingesting files without checking their true file signatures or content patterns allows vulnerabilities and data breaches to occur - becoming a cybersecurity issue.

#### 2) PROPOSED ARCHITECTURE:
The skeleton of this system can be built as a single, local Python app. Managing external web servers won't be necessary, although this project can definitely allow it.

The tech stack (so far) is as follows:
- Python + SQL (main languages)
- Streamlit (serves as our local web dashboard, but using Python instead of HTML, CSS, etc.)
- SQLite (serves as our local relational database storage for logs and hashes)
- NOTE: This project allows for more expansion on current ideas and technical stack.

#### 3) SYSTEM ANALYSIS ARTIFACTS (THE BLUEPRINT):

#### 4) UNIT TEST STRATEGY (PRE-IMPLEMENTATION):
