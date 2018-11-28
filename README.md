15-441 F16 Project

You can use git'*tag* to check 3 different checkpoints!


# Checkpoint 2
The main program structure is in `lisod.c`.

Logging module is in `log.c`.

Parsing module in `parse.c`, `parser.y` and `lexer.l`.

GET, POST, HEAD methods are handled in `request.c`.

Test Result:
```
./lisod 1917 4981 ./lisod.log ../tmp/lisod.lock ../tmp/www ../tmp/cgi/cgi_script.py ../tmp/grader.key ../tmp/grader.crt
Wait 2 seconds.
Server is running
ok
test_HEAD_headers (__main__.project1cp2tester) ... ----- Testing Headers -----
ok
test_HEAD (__main__.project1cp2tester) ... ----- Testing HEAD -----
ok
test_GET (__main__.project1cp2tester) ... ----- Testing GET -----
ok
test_POST (__main__.project1cp2tester) ... ----- Testing POST -----
ok
test_bad (__main__.project1cp2tester) ... ----- Testing Bad Requests-----
ok
test_big (__main__.project1cp2tester) ... ----- Testing Big file -----
ok
test_kill (__main__.project1cp2tester) ... kill it
ok

----------------------------------------------------------------------
Ran 11 tests in 19.241s

OK
{"scores": {"test_make": 1, "test_HEAD_headers": 1, "test_POST": 1, "server_start": 1, "test_git": 1, "use_select": 1, "test_big": 1, "test_bad": 1, "test_GET": 1, "test_HEAD": 1}}
```
