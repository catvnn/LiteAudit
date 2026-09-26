# LiteAudit

Welcome to the general frame of LiteAudit!

LiteAudit is a file-verification application that runs on your local computer. I'm calling it LiteAudit for now because it utilizes SQLite and it's a "lite"-weight application...



#### 1) PROBLEM:
Businesses and academic departments frequently ingest uploaded documents (PDFs, text files, etc.) for their daily operations. While there are antivirus software currently available, LiteAudit differs by being an application that has the ability to detect the structural anomalies of different documents. These problems can be: problematic SQL injections, script file renames, etc. Any individual, team or business that handles digital forms regularly can be at risk of allowing suspicious files to access their digital environment. Ingesting files without checking their true file signatures or content patterns allows vulnerabilities and data breaches to occur - becoming a cybersecurity issue.

#### 2) PROPOSED ARCHITECTURE:
The skeleton of this system can be built as a single, local Python app. Managing external web servers won't be necessary, although this project can definitely allow it.

The tech stack (so far) is as follows:
- Python + SQL (main languages)
- FastAPI (helps us validate specific data, etc.)
- Streamlit (serves as our local web dashboard, but using Python instead of HTML, CSS, etc.)
- SQLite (serves as our local relational database storage for logs and hashes)
- NOTE: This project allows for more expansion on current ideas and technical stack.

#### 3) SYSTEM ANALYSIS ARTIFACTS (THE BLUEPRINT):
<img width="1536" height="1024" alt="Flowchart + Architecture" src="https://github.com/user-attachments/assets/c817c6a9-25f6-4d9b-8581-e65911db51c4" />

<img width="1083" height="617" alt="image" src="https://github.com/user-attachments/assets/eddac1fe-a521-4419-8b3d-b64e66d7d877" />

<img width="1096" height="588" alt="image" src="https://github.com/user-attachments/assets/38f1c0da-88f6-4029-a00c-b490ec3492b0" />

#### 4) UNIT TEST STRATEGY (PRE-IMPLEMENTATION):
<img width="1536" height="1024" alt="3 Use Case Scenarios" src="https://github.com/user-attachments/assets/3c7f9dd3-0807-4c95-bfac-f112aaf4d1e1" />

#### 5) FINANCIAL ESTIMATES & BUSINESS MODEL:
Business Model Type: Business 2 Business Subscription

<img width="596" height="282" alt="image" src="https://github.com/user-attachments/assets/0cf854b4-b71f-4ddd-901a-f110d5478ba4" />

Basic users will have free access to 20 limited scans. The Business Plan will unlock unlimited features.

This financial model is inspired by how companies purchase Microsoft Office 365 licenses for all their employees, which can be up to $100/month depending on opted features. The Business Plan allows companies to purchase LiteAudit licenses for their employees as needed.

Break-Even Logic: Deploying LiteAudit through Snowflake can cost up to $100/month to keep running. Therefore, it can take up to 7 active Business Plan users a month to break even. The costs to deploy and keep the LiteAudit app running are fixed. There are no costs per active user.

Data Validation: https://www.microsoft.com/en-us/microsoft-365/business/microsoft-365-plans-and-pricing

#### 6) GAP ANALYSIS (CURRICULUM FEEDBACK):
In our previous IT database class, we learned to use MySQL as our database server. I have experience working with Microsoft SSMS professionally, which is essentially the same thing as MySQL, just with Microsoft configs. Learning SQLite will be something new for me personally, but my decision in selecting SQLite is that it utilizes Python as a programming language for the front-end development of this project. FastAPI (Python) and Streamlit were not introduced in traditional TTU IT curriculum, but I can assure you that these things are easy to pick up for this project.

I've been studying Python programming language for a few years now, I have experience working with it professionally in automation and application development. I also have experience working with SQL professionally. The learning gap I believe I need to fill is to utilize these languages in ways I have never tried before (e.g. in SQLite, etc.) I will definitely need to mess around with how these applications work for us to create LiteAudit!


#### 7) AI TRANSPARENCY LOG:
- So far, I have used generative AI to help me create some of the visual images you see above. This just helped save me some time in creating neat flowcharts and graphs.
- I am on board with using generative AI as a time-saving tool. However, for this project, it would be great to form a team that has foundational understanding of how to write SQL queries and program in Python. A foundational background in understanding application development would be a bonus as well.

====================================================================================

Catherine Nguyen
