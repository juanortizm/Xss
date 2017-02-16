import unittest
from urllib2 import urlopen
from BeautifulSoup import BeautifulSoup
import urllib
import urlparse
import threading
import urllib2
import requests 
from cookielib import CookieJar
import sqlite3
import time
import os,sys,inspect
currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir) 
import scanxss


class LearningCase(unittest.TestCase):
    def test_url_splitting(self):
        url_testcase1 = 'https://domain.com/uri1/uri2'
        url_testcase2 = 'https://domain.com/uri1/uri2?query=??'
        testcase1 = scanxss.splitUrl(url_testcase1);
        testcase2 = scanxss.splitUrl(url_testcase2);
        
        self.assertEqual(testcase1.get('protocol'), 'https://');
        self.assertEqual(testcase1.get('domain'), 'domain.com');
        self.assertEqual(testcase1.get('path'), '/uri1/uri2');
        self.assertEqual(testcase1.get('query'), '');
        self.assertEqual(testcase1.get('url'), url_testcase1);

        self.assertEqual(testcase2.get('protocol'), 'https://');
        self.assertEqual(testcase2.get('domain'), 'domain.com');
        self.assertEqual(testcase2.get('path'), '/uri1/uri2');
        self.assertEqual(testcase2.get('query'), 'query=??');
        self.assertEqual(testcase2.get('url'), url_testcase2);

    def test_get_Links_From_html(self):
    	inputs = dict({'url':'https://google-gruyere.appspot.com/498717463845/','protocol':'https://','domain': 'google-gruyere.appspot.com','path':'/498717463845/','query':'','address':'https://google-gruyere.appspot.com/498717463845/'});
    	file = open('./mocks/mock_html_links.txt', 'r');
    	page = file.read();
    	soup = BeautifulSoup(page);
        links = list();
    	scanxss.getLinks(soup,inputs,links,{});
    	data1 = scanxss.splitUrl(links[0].get('url'));
        data2 = scanxss.splitUrl(links[1].get('urlToTest'));
    	self.assertEqual(len(links),2);
    	self.assertTrue(len(data1.get('query')) == 0)
        self.assertTrue(len(data2.get('query').split('&')) >= 1)

    def test_get_forms_From_html(self):
    	inputs = dict({'url':'https://www.linkedin.com/','protocol':'https://','domain': 'www.linkedin.com','path':'/','query':'','address':'https://www.linkedin.com'});
    	file = open('./mocks/mock_html_forms.txt', 'r');
    	page = file.read();
    	soup = BeautifulSoup(page);
        links = list();
        posts = list();
    	scanxss.getForms(soup,inputs,links,{},posts);
    	self.assertEqual(len(posts),1);
    	self.assertEqual(len(links),1);
    	self.assertEqual(links[0].get('url'),"https://www.linkedin.com/languageSelector")

   
    def test_find_xss_in_response_with_script_tag(self):
        file = open('./mocks/mock_xss_response.txt', 'r');
        page = file.read();
        soup = BeautifulSoup(page);
        isXssVulnerability = scanxss.findXssInResponse("https://test.com",soup,'<script>alert("123")</script>')
        self.assertTrue(isXssVulnerability)
            
    def test_find_xss_inline_parameter(self):
        file = open('./mocks/mock_inline_xss_response.txt', 'r');
        page = file.read();
        soup = BeautifulSoup(page);
        isXssVulnerability = scanxss.findXssInResponse("https://test.com",soup,"javascript:alert('123')")
        self.assertTrue(isXssVulnerability)

    def test_find_xss_Without_result(self):
        file = open('./mocks/mock_response_without_xss.txt', 'r');
        page = file.read();
        soup = BeautifulSoup(page);
        isXssVulnerability1 = scanxss.findXssInResponse("https://test.com",soup,"javascript:alert('123')")
        isXssVulnerability2 = scanxss.findXssInResponse("https://test.com",soup,'<script>alert("123")</script>')
        self.assertEqual(isXssVulnerability1,False)
        self.assertEqual(isXssVulnerability2,False)
            
    def test_response_with_bloquequotes(self):
        file = open('./mocks/mock_response_with_bloquequotes.txt', 'r');
        page = file.read();
        soup = BeautifulSoup(page);
        isXssVulnerability1 = scanxss.findXssInResponse("https://test.com",soup,"javascript:alert('123')")
        isXssVulnerability2 = scanxss.findXssInResponse("https://test.com",soup,'<script>alert("123")</script>')
        self.assertEqual(isXssVulnerability1,False)
        self.assertEqual(isXssVulnerability2,False)
            
    def test_response_with_bloquequotes_with_xss(self):
        file = open('./mocks/mock_response_with_bloquequotes_and_xss.txt', 'r');
        page = file.read();
        soup = BeautifulSoup(page);
        isXssVulnerability1 = scanxss.findXssInResponse("https://test.com",soup,"javascript:alert('123')")
        isXssVulnerability2 = scanxss.findXssInResponse("https://test.com",soup,'<script>alert("123")</script>')
        self.assertEqual(isXssVulnerability1,False)
        self.assertEqual(isXssVulnerability2,True)        


def main():
    unittest.main()

if __name__ == "__main__":
    main()