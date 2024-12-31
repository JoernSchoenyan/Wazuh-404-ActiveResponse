# Wazuh Active Response against malicious 404 traffic
This Active Response for Wazuh compares events with 404 status codes from Apache, Nginx or similar against a database and blocks IPs that scan your websites and applications for vulnerabilities.

## What is this all about?
Every web server is scanned daily for vulnerabilities: bugs in Wordpress installations and extensions, database backups, open login pages, even backdoors left by other crackers. I want to make my life easier and the lives of the bad guys harder.

```
139.9.84.38 - - [22/Dec/2024:04:07:28 +0000] "GET /blog/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.0" 404 974 "-"
139.9.84.38 - - [22/Dec/2024:04:07:28 +0000] "GET /workspace/drupal/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.0" 404 974 "-"
139.9.84.38 - - [22/Dec/2024:04:07:29 +0000] "GET /panel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.0" 404 974 "-"
139.9.84.38 - - [22/Dec/2024:04:07:29 +0000] "GET /public/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.0" 404 974 "-"
139.9.84.38 - - [22/Dec/2024:04:07:30 +0000] "GET /apps/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.0" 404 974 "-"
139.9.84.38 - - [22/Dec/2024:04:07:31 +0000] "GET /app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.0" 404 974 "-"
139.9.84.38 - - [22/Dec/2024:04:07:31 +0000] "GET /index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello HTTP/1.0" 404 974 "-"
139.9.84.38 - - [22/Dec/2024:04:07:32 +0000] "GET /public/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello HTTP/1.0" 404 974 "-"
139.9.84.38 - - [22/Dec/2024:04:07:32 +0000] "GET /index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?echo(md5(\"hi\"));?>+/tmp/index1.php HTTP/1.0" 404 974 "-"
139.9.84.38 - - [22/Dec/2024:04:07:33 +0000] "GET /index.php?lang=../../../../../../../../tmp/index1 HTTP/1.0" 404 974 "-"
139.9.84.38 - - [22/Dec/2024:04:07:33 +0000] "GET /containers/json HTTP/1.0" 404 974 "-"
```

This is a small example what happens. We see a lot of 404 HTTP status codes. I'm creating a blacklist of URLs/paths which are clearly signs of vulnerability scanning and this active response for Wazuh blocks attackers using these URLs.

## Wazuh settings
You need the the active response script, the database file and of course the Wazuh agent on the web server. Here are settings for your Wazuh server (/var/ossec/etc/ossec.conf):

```
  <command>
    <name>linux-custom-ar-404-blacklist</name>
    <executable>custom-ar-404-blacklist.py</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>linux-custom-ar-404-blacklist</command>
    <location>local</location>
    <rules_id>31101</rules_id>
    <timeout>43200</timeout>
  </active-response>
```

Source: [Wazuh: Custom active response scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)

Of course, don't forget to add the log files of your Apache2/nginx/whatever to the ossec.conf of your Wazuh agent. This very much depends on your exact setup, but as an example:

```
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/www/vhosts/*/logs/access_ssl_log</location>
  </localfile>
```

## The database
I will push updates from time to time for the database with suspicious URLs but you'll be able to add them yourself in the near future, too. If you want URLs to be added, you can also open an issue. I've included an example file of the database. You can see the content of the database like this:

```
sqlite3 /var/ossec/etc/suspicious_paths.db
SELECT * FROM suspicious_paths;
```
