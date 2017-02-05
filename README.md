# Xss

### INSTALLATION

#### git clone https://github.com/jcodz/Xss.git
#### cd /Xss
#### sudo pip install -r requirements.txt

#### If you run the script and it says 'Error connecting to database' You need to install SQLITE executing 'brew install sqlite3' or download at page. 

### RUN SCRIPT  

#### To run xss scanner you have to execute 'python scanxss.py'

#### Set query params 'https://domain.com/uri1/uri11?query=??' , '??' will be replace by payload.

#### Set cookies like 'COOKIENAME=COOKIEVALUE'

### RESULTS OF SCANNER

#### To see the results of scanner you have to run 'python results.py'

### DELETE DATABASE 

#### scannxss.py first delete all results of database and then analyze the page , but if you wish to delete all database content you have to run 'python deleteDB.py'

### RUN TESTS

#### To run tests execute 'python tests.py'

### DEMO IMAGES

##### RUN SCRIPT

###### SET URL,THREADS AND COOKIES

![Screenshot](/demo/Screen Shot 2017-02-02 at 2.58.18 PM.png)
#
##### ANALIZING URL 
#
![Screenshot](/demo/Screen Shot 2017-02-02 at 3.05.14 PM.png)
#
##### RESULTS
#
![Screenshot](/demo/Screen Shot 2017-02-02 at 3.06.10 PM.png)


