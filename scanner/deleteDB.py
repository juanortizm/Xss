import sqlite3





def databaseConnection():
	try:
		database = sqlite3.connect('vuln.db',check_same_thread = False);
		cursor = database.cursor();
		cursor.execute('''DELETE FROM VULNS''');
		database.commit();
		return database;
	except:
		print setTextStyle("asdas");
		sys.exit(0);


databaseConnection();		