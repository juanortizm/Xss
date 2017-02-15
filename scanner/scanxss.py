from urllib2 import urlopen
from BeautifulSoup import BeautifulSoup
import urllib
import urlparse
import threading
import sys
import urllib2
import requests 
from cookielib import CookieJar
import sqlite3
import time
import requests
import multiprocessing
import tabulate
import sqlite3

########### CONSTANTS ########### 
 
#.............SQL QUERIES.............#
CREATE_TABLE = '''CREATE TABLE IF NOT EXISTS VULNS (id INTEGER, url TEXT, vuln TEXT, method TEXT, postParams TEXT);'''
DELETE_TABLE_QUERY = '''DELETE FROM VULNS''';
INSERT_VULN_QUERY = '''INSERT INTO VULNS(url, vuln,method,postParams)VALUES(?,?,?,?)''';
SELECT_VULNS_QUERY = '''SELECT url, vuln, method, postParams FROM VULNS'''; 
#............END SQL QUERIES..............#
#.................ERRORS..................#
ERR_DB_CONNECTION = "Error connecting to database";
ERR_PARSING_INPUTS = "Can not parse inputs";
ERR_INVALID_URL = 'Invalid URL, format https://domain.com?queryname=??';
ERR_PAYLOADS_NOT_EXISTS = 'payloads.txt not exist'
ERR_OPEN_PAGE = 'Verify your conection or the url';
ERR_SUBMIT_FORM = "fail to submit form";
#...............END ERRORS................#
#...............MESSAGES..................#
LINKS_FOUNDED = "Links founded %s";
POSTS_FOUNDED = "Posts founded %s";
SEARCHING_XSS = "Searching XSS";
SEARCHING_LINKS = "Serching Links...";
EXECUTE_RESULTS_TABLE = "Execute 'python results.py' when script finish.";
WITHOUT_VULNERABILITIES = "there are not vulnerabilities in url that you enter";
INICIAL_MESSAGE = """
	XSS.py search web xss vulnerabilities by analyzing the html code.
	If input url has parameters then first will analyze said url with 
	the list available in payloads.txt,then vulnerabilities found will
	be tested in the rest of the links in HTML code. But if the input 
	url does not contain parameters, then the available links will be 
	searched and then , payloads will be applied. \n\n\n""";
#.............END MESSAGES................#

	    	

def main():

	links = list();
	posts = list();
 	inputs = getInputs();										
	payloads = readPayloads();	
	cursor = database.cursor();	
	 
	links.append(createLink(inputs.get('url'),inputs.get('cookies'),inputs.get('url')));
	
	for link in links:		
		splitedUrl = splitUrl(link.get('url'));	
		soup,cookiejar = openPage(link.get('url'),link.get('cookies'));

		if splitedUrl: 
			getLinks(soup,splitedUrl,links,cookiejar);                      # getLinks and getForms 							
			getForms(soup,splitedUrl,links,cookiejar,posts);	 		    # fill links array	

			if link.get('type') == 'get':
				if splitedUrl.get('query'):
					print setTextStyle(SEARCHING_XSS);
					evalLinks(link.get('urlToTest'),payloads,link.get('cookies'),inputs.get('threads'))
			else:
				evalPostForms(link.get('url'),link.get('params'),payloads,link.get('cookies'),inputs.get('threads'))
	
	for vuln in vulnerabilities:
		if vuln:
			cursor.execute(INSERT_VULN_QUERY, (vuln.get('url'),vuln.get('payload'),vuln.get('method'),str(vuln.get('postParams'))))
			database.commit();

	showResult();		
	
	print setTextStyle(LINKS_FOUNDED % (str(len(links)-1)));
	print setTextStyle(POSTS_FOUNDED % (str(len(posts))));		
	print setTextStyle(EXECUTE_RESULTS_TABLE);


def createLink(url,cookies,urlToTest=""):
	return dict({'url':url,'cookies':cookies,'urlToTest':urlToTest,'type':'get'})
def createPost(url,cookies,params):
	return dict({'url':url,'cookies':cookies,'params':params,'type':'post'})
				
def databaseConnection():
	try:
		database = sqlite3.connect('vuln.db',check_same_thread = False);
		cursor = database.cursor();
		cursor.execute(CREATE_TABLE);
		database.commit();
		cursor.execute(DELETE_TABLE_QUERY);
		database.commit();
		return database;
	except:
		print setTextStyle(ERR_DB_CONNECTION);
		sys.exit(0);

def getInputs():
	try:
		url = raw_input(setTextStyle('URL: ')).strip();
		threads = raw_input(setTextStyle('THREADS: ')).strip();
		cookie = raw_input(setTextStyle('COOKIE (enter to continue): ')).strip();
		inputs = dict();
		cookies = dict();

		if not threads:
			threads = 1;
		else:
			threads = int(threads);


		while cookie:
			ck = cookie.split('=');
			if len(ck) > 1:
				cookies.update({ck[0]:ck[1]})
			cookie = raw_input(setTextStyle('COOKIE (enter to continue): ')).strip();

		inputs['url'] = url;
		inputs['threads']	= threads;
		inputs['cookies'] = cookies;
		return inputs;
	except: 
		print setTextStyle(ERR_PARSING_INPUTS);
		sys.exit(0);	


def splitUrl(url):
	try: 
		parser = urlparse.urlparse(url);
		protocol = '%s%s' % (parser.scheme,'://');
		domain = parser.netloc;
		path = parser.path;
		query = parser.query;
		address = '%s%s%s' % (protocol,domain,path);

		if protocol and domain and path and address:
			data = dict({'url':url,
						 'protocol':protocol,
						 'domain': domain,
						 'path':path,
						 'query':query,
						 'address':address});
			return data;
		else:
			print setTextStyle(ERR_PARSING_INPUTS);
	except:
		print setTextStyle(ERR_PARSING_INPUTS);	

def readPayloads():
	try:
		file = open('payloads.txt', 'r'); 
		lines = file.readlines();
		payloads = [x.strip() for x in lines];
		file.close();
		return payloads;
	except:
		print setTextStyle(ERR_PAYLOADS_NOT_EXISTS);
		sys.exit(0);


def openPage(url,cookies):
	try:
		session = requests.Session();
		page = session.get(url,cookies=cookies);
		soup = BeautifulSoup(page.text);
		cookies = session.cookies.get_dict();
		return soup,cookies;
	except:
		dummy = ""		

def getLinks(soup,data,links,cookies):
	START_QUERY_PARAM = '?';
	NEW_QUERY_PARAM = '=??&';
	
	for a in soup.findAll('a', href=True):
		href = urlparse.urlparse(a.get('href'));
		if (not href.netloc or href.netloc == data.get('domain')):         #Only get links of the same domain
			
			url = ""
			urlTest = ""
			if not href.netloc:
				link = '%s%s%s' % (data.get('protocol'),data.get('domain'),a.get('href'));
				url = link
			else: 
				url = a.get('href')
				
			if href.query:	
				queryParser = urlparse.parse_qsl(href.query);
				queryParams = START_QUERY_PARAM;
				for x,y in queryParser:
					queryParams += x + NEW_QUERY_PARAM;
				queryParams = queryParams[:-1]
				urlTest = url.split('?')[0] + queryParams     	    
			if not inLinks(url,links):	
				links.append(createLink(url,cookies,urlTest))
	return links; 	

def getForms(soup,data,links,cookies,posts):
	NEW_QUERY_PARAM = '=??&';
	START_QUERY_PARAM = '?';
	getForms = list();
	postForms = list();
	
	for form in soup.findAll('form'):
		domain = '' ;

		if form.get('action'):
			action = urlparse.urlparse(form.get('action'));
			domain = action.netloc.replace('www.','');
			address = '%s%s%s' % (data.get('protocol'),domain,action.path);
			url = action.geturl().replace('www.','');
			
		if domain == data.get('domain') or not domain or form.get('action') == START_QUERY_PARAM: 
			if form.get('method') in ['GET','get',None] :
				inputs = form.findAll('input');
				queryParams = START_QUERY_PARAM;

				for element in inputs:
					if element.get('type') != 'submit':
						queryParams += str(element.get('name')) + NEW_QUERY_PARAM;
				queryParams = queryParams[:-1];
				if not form.get('action'):
					link = data.get('address') + queryParams;
				else:
					if data.get('domain') in form.get('action'):
						link = form.get('action') + queryParams;
					else:
						link = 	data.get('protocol') + data.get('domain') +  form.get('action') + queryParams;
				if not inLinks(link,links):
					links.append(createLink(link,cookies,link));
                
			else: 
				inputs = form.findAll('input')
				params = list();
				for element in inputs:
					if element.get('type') != 'submit':
						params.append(str(element.get('name')));
				textareas = form.findAll('textarea');	
				for textarea in textareas:
					params.append(str(textarea.get('name')));

				if not form.get('action') or form.get('action') == START_QUERY_PARAM:
					link = data.get('address'); 
				else:
					if data.get('address')[-1:] != '/':
						link = data.get('address')+form.get('action')
					else:
						link = data.get('address')[:-1]+form.get('action');	
				if params:
					if not inPosts(posts,link):
						links.append(createPost(link,cookies,params))
						posts.append([link,params]);							 		


def inLinks(url,links):
	for link in links:
		if url == link.get('url'):
			return True
	return False	      

def inPosts(posts,url):
	for post in posts:
		if url == post[0]:
			return True
	return False

def evalLinks(link,payloads,cookies,threads):
	pool = multiprocessing.Pool(processes=threads)
	print setTextStyle("Testing "+ link)
	for payload in payloads:
		pool.apply_async(findXssQueries,args=(link,payload,cookies),callback=vulnerabilities.append);
	pool.close()	
	pool.join()		

def findXssQueries(link,payload,cookies):
	try:
		QUERY_VAR = '??'
		cursor = database.cursor();
		quoted_query = urllib.quote(payload);
		url_payload = link.replace(QUERY_VAR,quoted_query);
		session = requests.Session();
		page = session.get(url_payload,cookies=cookies);
		if page.status_code == 200:
			soup = BeautifulSoup(page.text);
			xss = findXssInResponse(link,soup,payload)    
			if xss:
				return createResult(link,'get',payload)
	except:
		dummy = ""
			

def evalPostForms(link,params,payloads,cookies,threads):
	pool = multiprocessing.Pool(processes=threads)
	print setTextStyle("Testing Post "+ link)
	for payload in payloads:
		pool.apply_async(findXssOnPostForms,args=(link,params,payload,cookies),callback=vulnerabilities.append);
	pool.close()	
	pool.join()		
		# findXssOnPostForms(form[0],form[1],payloads,cookieJarResponse)


def findXssOnPostForms(link,inputs,payload,cookies):
	EQUALS = '=';
	session = requests.Session();
	cursor = database.cursor();

	data = {}
	for inputData in inputs:
		data[inputData] = payload

	try:	
		session = requests.Session();
		page = session.post(link,data=data,cookies=cookies);
		soup = BeautifulSoup(page.text)
		xss = findXssInResponse(link,soup,payload)  
		if xss:
			return createResult(link,'post',payload,data)
			# cursor.execute(INSERT_VULN_QUERY, (link,payload))
			# database.commit();
	except:
		dummy = ""
			
		
def findXssInResponse(link,soup,payload):
	SCRIPT_TAG = "<script>";
	inlineParams = list(['<a onclick="','<img src="','<IFRAME src="'])
	if SCRIPT_TAG in payload:
		blockquotes = soup.findAll('blockquote')
		if not blockquotes:
			for elem in soup.findAll(['script']):
				if str(elem.extract()) == payload:
					return True  
		else:
			inBlockquote = False
			for blockquote in blockquotes:
				for elem in blockquote.findAll(['script']):
					if str(elem.extract()) == payload:
						inBlockquote = True;
			if not inBlockquote:
				for elem in soup.findAll(['script']):
					if str(elem.extract()) == payload:
						return True  		
	else:
		for param in inlineParams:
			if  param+payload in str(soup):
				return True    

	return False			 
				
def createResult(url,method,payload,postParams={}):
	return dict({'url':url,'method':method,'payload':payload,"postParams":postParams})

def setTextStyle(text):
	RED = '\033[91m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	END = '\033[0m'
	return BOLD + RED + text + END;

def showResult():
	cursor = database.cursor();
	result = []		
	data = cursor.execute(SELECT_VULNS_QUERY)
	headers = ["URL", "PAYLOAD","METHOD","POSTPARAMS"]
	for row in data:
		result.append([row[0], row[1], row[2] , row[3]])
	print
	print tabulate.tabulate(result, headers)
	print 
	print
	database.close(); 


if __name__ == '__main__':

	print setTextStyle(INICIAL_MESSAGE);
	vulnerabilities = list();
	database = databaseConnection();
	main();
