# Apache Logs Analyzer
A simple apache logs analyzer that detects the following:
* list of unique IP addresses
* list of unique IP addresses with country and number of hits
* list of all activity per IP address to individual
* detect SQL injections
* detect remote file inclusion
* detect web shells attack

***Notes:***

this script serves as my test assignment from [Horangi](https://horangi.com/) which include the following instructions:

> Build a python script that reads apache logs (the link to the sample file provided below) line by line and returns the following information to file(s):
> 
> * list of unique IP addresses as a flat text file
> * list of unique IP addresses with country and number of hits as a flat text file
> * list of all activity per IP address to individual flat text files per IP
> * detect SQLi with found entries to flat text file
> * detect remote file inclusion with found entries to flat text file
> * detect web shells with found entries to flat text file

> Download:
> https://horangi.box.com/s/9dj3vl4ikzt19td7a9520t7xp4fp1km9
> 
> Deliverables: source code in github, developer guide, user guide.


## Installation Guide
* Clone this repo and enter the script folder

  `
  git clone https://github.com/ryanermita/apache-logs-analyzer.git && cd apache-logs-analyzer/
  `

* install [virtualenv](https://virtualenv.pypa.io/en/stable/) to isolate packages used in this script
* create virtualenv instance

  `
  virtualenv venv
  `

* enter the virtualenv instance

  `
  . venv/bin/activate
  `

* install dependency packages

  `
  pip install -r requirements.txt
  `

## User Guide
all of the commands will run inside the virtualenv project root directory.
Run this command below inside the project root directory before using the script.

  `
  . venv/bin/activate
  `


* script description and command list

  `
  python src/parse_logs.py -h
  `

* Detecting unique IPs with corresponding country and number of hits

  `
  python src/parse_logs.py -c get_unique_ips -F <apache logs to analyze>
  `

* Detecting all activities per IP

  `
  python src/parse_logs.py -c activities_per_ip -F <apache logs to analyze>
  `

* Detecting SQL injection attacks

  `
  python src/parse_logs.py -c get_sql_injections -F <apache logs to analyze>
  `

* Detecting remote file inclusion attack

  `
  python src/parse_logs.py -c get_file_inclusion -F <apache logs to analyze>
  `

* Detecting web shells attack

  `
  python src/parse_logs.py -c get_web_shells_attack -F <apache logs to analyze>
  `
